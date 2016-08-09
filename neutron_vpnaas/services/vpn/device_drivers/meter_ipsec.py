# Copyright (c) 2016 Jin Jing Lin, IBM.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import time
import os
import netaddr
import traceback
from neutron.agent.linux import iptables_manager
from neutron.common import rpc as n_rpc
from neutron import context
from oslo_config import cfg
from oslo_log import log as logging
from oslo_service import loopingcall

from neutron_vpnaas.services.vpn.device_drivers import ipsec

LOG = logging.getLogger(__name__)

meter_opts = [
    cfg.BoolOpt('vpn_meter_enable',
                default=False,
		help=_('Enable flag for VPN metering function')),
    cfg.IntOpt('vpn_measure_interval',
               default=30,
	       help=_('The interval between two metering measures')),
    cfg.IntOpt('vpn_report_interval',
	       default=300,
	       help=_('The interval between two metering reports'))
]

cfg.CONF.register_opts(meter_opts, 'meter')

WRAP_NAME = 'neutron-vpn-mete'
TOP_CHAIN = WRAP_NAME + '-FORWARD'
RULE_OUT = '-o-'
RULE_IN = '-i-'

MAX_CHAIN_LEN_WRAP = 11
MAX_CHAIN_LEN_NOWRAP = 28

def get_chain_name(chain_name, wrap=True):
    if wrap:
        return chain_name[:MAX_CHAIN_LEN_WRAP]
    else:
        return chain_name[:MAX_CHAIN_LEN_NOWRAP]


class MeterProcess(object):
    def __init__(self, conf, process_id, vpnservice, namespace):
        if self.conf.meter.vpn_meter_enable:
            self.meter_iptables_manager = iptables_manager.IptablesManager(
	        state_less=True,
	        namespace=namespace,
	        binary_name='neutron-vpn-meter',
	        use_ipv6=False)
    
    def conn_id_check(self, vpnservice):
       #check whether the conn_id is existing before, it yes, just empty the new rules and delete the old ones
       	config_file = os.path.join(self.etc_dir, 'ipsec.conf')
	conn_ids = []

	if os.path.isfile(config_file):
	    ipsec_conns = vpnservice['ipsec_site_connections']
	    fp = open(config_file, 'r')
	    lines = fp.readlines()
	    fp.close()
	    for line in lines:
	        if line.find('conn ') == -1 or line.find('%default') != -1:
		    continue
		conn_ids.append(line.split()[1])
	    
	    for ipsec_conn in ipsec_conns:
	        if ipsec_conn['id'] in conn_ids:
		    conn_ids.remove(ipsec_conn['id'])
         
	return conn_ids


class MeterIPsecDriver(ipsec.IPsecDriver):

    def __init__(self, vpnservice, host):
       super(MeterIPsecDriver, self).__init__(vpnservice, host)
       if self.conf.meter.vpn_meter_enable:
           measure_interval = self.conf.meter.vpn_measure_interval
	   self.metering_loop = loopingcall.FixedIntervalLoopingCall(
	       self._metering_loop
	   )
	   self.last_report = 0
	   self.metering_loop.start(interval=measure_interval)
	   self.tenant_conn_ids = {}
           self.conn_tenant_id = {}
           self.metering_out_infos = {}
	   self.metering_in_infos = {}
	   self.metering_infos = [self.metering_out_infos, self.metering_in_infos]

    def destroy_process(self, process_id):
        if self.conf.meter.vpn_meter_enable:
	    self._add_metering_infos()
	if process_id in self.processes:
	    process = self.processes[process_id]
	    process.disable()
	    vpnservice = process.vpnservice
	    if vpnservice:
	        self._update_nat(vpnservice, self.remove_nat_rule)
		if self.conf.meter.vpn_meter_enable:
		    self._update_metering_rule(vpnservice, [], self.remove_metering_rule)
                    self._clean_tenant_conn_mapping(vpnservice)
	    del self.processes[process_id]

    def _clean_tenant_conn_mapping(self, vpnservice):
        # delete the tenant-conn mapping entry when the process is destroy
        if not vpnservice:
            return
        tenant_id = vpnservice['project_id']
        for ipsec_site_connection in vpnservice['ipsec_site_connections']:
            conn_id = ipsec_site_connection['id']
            del self.conn_tenant_id[conn_id]
        del self.tenant_conn_ids[tenant_id]

    def _sync_tenant_conn_mapping(self, vpnservice, conn_ids):
        # update the global tenant - conn mapping
        if not vpnservice:
            return
        tenant_id = vpnservice['project_id']
        for ipsec_site_connection in vpnservice['ipsec_site_connections']:
            ipsec_conn_id = ipsec_site_connection['id']
            self.conn_tenant_id[ipsec_conn_id] = tenant_id
            if self.tenant_conn_ids.get(tenant_id):
                if ipsec_conn_id not in self.tenant_conn_ids.get(tenant_id):
                    self.tenant_conn_ids[tenant_id].append(ipsec_conn_id)
            else:
                self.tenant_conn_ids[tenant_id] = []
                self.tenant_conn_ids[tenant_id].append(ipsec_conn_id)

        if conn_ids:
            for conn_id in conn_ids:
                del self.conn_tenant_id[conn_id]
                if conn_id in self.tenant_conn_ids[tenant_id]:
                    self.tenant_conn_ids[tenant_id].remove(conn_id)

    def _update_metering_rule(self, vpnservice, conn_ids, func):
        router_id = vpnservice['router_id']
	rules_del = []
	if conn_ids:
	    for conn_id in conn_ids:
	        meter_chain_o = get_chain_name(WRAP_NAME+RULE_OUT+conn_id, wrap=False)
		meter_chain_i = get_chain_name(WRAP_NAME+RULE_IN+conn_id, wrap=False)
		rules_del.append(meter_chain_o)
		rules_del.append(meter_chain_i)

	for ipsec_site_conn in vpnservice['ipsec_site_connections']:
	    connection_id = ipsec_site_conn['id']
	    peer_cidrs = ipsec_site_conn['peer_cidrs']

	    func(router_id, connection_id, peer_cidrs, rules_del, top=True)

	self.meter_iptables_apply(router_id)


    def add_metering_rule(self, router_id, connection_id, peer_cidrs, rules, top=False):
        router = self.routers.get(router_id)
	if not router:
	    return
	process_id = router
	process = self.processes.get(process_id)
        if not process:
            return
	iptables_manager = process.meter_iptables_manager

	if rules:
	    for rule in rules:
	        iptables_manager.ipv4['filter'].remove_chain(rule, wrap=False)

	chain_name_out = get_chain_name(WRAP_NAME+RULE_OUT+connection_id, wrap=False)
	chain_name_in = get_chain_name(WRAP_NAME+RULE_IN+connection_id, wrap=False)
	iptables_manager.ipv4['filter'].add_chain(chain_name_out, wrap=False)
	iptables_manager.ipv4['filter'].add_chain(chain_name_in, wrap=False)
        iptables_manager.ipv4['filter'].add_rule(TOP_CHAIN, '-j '+chain_name_out, wrap=False)
	iptables_manager.ipv4['filter'].add_rule(TOP_CHAIN, '-j '+chain_name_in, wrap=False)

	# empty the conn-chain for if there is old connection rules, delete it and then write the new ones
	iptables_manager.ipv4['filter'].empty_chain(chain_name_out, wrap=False)
	iptables_manager.ipv4['filter'].empty_chain(chain_name_in, wrap=False)

	for peer_cidr in peer_cidrs:
	    if netaddr.IPNetwork(peer_cidr).version == 6:
	        continue
	    ipt_rule_in = '-s %s -j RETURN' % peer_cidr
	    ipt_rule_out = '-d %s -j RETURN' % peer_cidr
	    iptables_manager.ipv4['filter'].add_rule(chain_name_in, ipt_rule_in, wrap=False, top=True)
	    iptables_manager.ipv4['filter'].add_rule(chain_name_out, ipt_rule_out, wrap=False, top=True)
	    
    def remove_metering_rule(self, router_id, connection_id, peer_cidrs, rules, top=False):
        router = self.routers.get(router_id)
	if not router:
	    return
	process_id = router
        process = self.processes.get(process_id)
        if not process:
            return
	iptables_manager = process.meter_iptables_manager

	chain_name_out = get_chain_name(WRAP_NAME+RULE_OUT+connection_id, wrap=False)
	chain_name_in = get_chain_name(WRAP_NAME+RULE_IN+connection_id, wrap=False)
	iptables_manager.ipv4['filter'].remove_chain(chain_name_out, wrap=False)
	iptables_manager.ipv4['filter'].remove_chain(chain_name_in, wrap=False)

    def meter_iptables_apply(self, router_id):
        router = self.routers.get(router_id)
	if not router:
	    return
	process_id = router
	process = self.processes.get(process_id)
        if not process:
            return
	iptables_manager = process.meter_iptables_manager
	iptables_manager.apply()

    def _metering_notification(self):
        for i in range(0, 2):
	    for connection_id, info in self.metering_infos[i].items():
	        data = {'connection_id': connection_id,
		        'tenant_id': self.conn_tenant_id.get(connection_id),
			'pkts': info['pkts'],
			'bytes': info['bytes'],
			'time' : info['time'],
			'first_update': info['first_update'],
			'last_update': info['last_update'],
			'host': self.host}

	        LOG.debug("Send VPN metering report: %s" % data)
		notifier = n_rpc.get_notifier('metering')
		if i == 0:
		    notifier.info(self.context, 'vpn.meter.tx', data)
		else:
		    notifier.info(self.context, 'vpn.meter.rx', data)

		info['pkts'] = 0
		info['bytes'] = 0
		info['time'] = 0

    def _purge_metering_info(self):
        deadline_timestamp = int(time.time()) - self.conf.meter.vpn_report_interval
	for i in range(0, 2):
	    conn_ids = []
	    for connection_id, info in self.metering_infos[i].items():
	        if info['last_update'] < deadline_timestamp:
		    conn_ids.append(connection_id)

            for connection_id in conn_ids:
	        del self.metering_infos[i][connection_id]

    def _get_traffic_counters(self, context, routers):
        accs_out = {}
	accs_in = {}
	accs = [accs_out, accs_in]
	for router in routers:
	    if not router:
	        continue
	    process_id = router
	    process = self.processes.get(process_id)
            if not process:
                continue
	    iptables_manager = process.meter_iptables_manager
	    tenant_id = process.vpnservice['project_id']
	    conn_ids = self.tenant_conn_ids[tenant_id]
	    for conn_id in conn_ids:
	        chain_out = get_chain_name(WRAP_NAME+RULE_OUT+conn_id, wrap=False)
		chain_in = get_chain_name(WRAP_NAME+RULE_IN+conn_id, wrap=False)
		chain = [chain_out, chain_in]
                chain_accs = [{}, {}]
		for i in range(0, 2):
		    try:
		        chain_accs[i] = iptables_manager.get_traffic_counters(
			    chain[i], wrap=False, zero=True)
		    except Exception as e:
                        LOG.info(traceback.format_exc())
		        continue
		    if not chain_accs[i]:
		        continue

		    acc = accs[i].get(conn_id, {'pkts': 0, 'bytes': 0})
		    acc['pkts'] += chain_accs[i]['pkts']
		    acc['bytes'] += chain_accs[i]['bytes']

		    accs[i][conn_id] = acc
	return accs

    def _add_metering_info(self, connection_id, index, pkts, bytes):
        ts = int(time.time())
	info = self.metering_infos[index].get(connection_id, {'bytes': 0,
	                                                      'pkts': 0,
							      'time': 0,
							      'first_update': ts,
							      'last_update': ts})
        
	info['bytes'] += bytes
	info['pkts'] += pkts
	info['time'] += ts - info['last_update']
	info['last_update'] = ts

	self.metering_infos[index][connection_id] = info
	return info
    
    def _add_metering_infos(self):
	accs = self._get_traffic_counters(self.context, self.routers.values())
	if not accs:
	    return

	for i in range(0, 2):
	    for connection_id, acc in accs[i].items():
	        self._add_metering_info(connection_id, i, acc['pkts'], acc['bytes'])


    def _metering_loop(self):
        self._add_metering_infos()

	ts = int(time.time())
	delta = ts - self.last_report

	report_interval = self.conf.meter.vpn_report_interval
	if delta > report_interval:
	    self._metering_notification()
	    self._purge_metering_info()
	    self.last_report = ts
