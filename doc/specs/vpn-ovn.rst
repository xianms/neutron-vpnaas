..
 This work is licensed under a Creative Commons Attribution 3.0 Unported
 License.

 http://creativecommons.org/licenses/by/3.0/legalcode

=========================
VPNaaS for OVN Networking
=========================

Launchpad blueprint:

https://blueprints.launchpad.net/neutron/+spec/vpn-ovn

This blueprint covers the support for VPNaaS with OVN networking by adding a
new centralized VPNaaS agent on a group of HA nodes. The new VPN agent will
create a namespace on the node and connect the namespace with the OVN
distributed logical router, and run the Swan process in the namespace.

Problem Description
===================

Currently VPNaaS service plugin only has support for the reference Neutron
software routers, such as neutron L3 router. It can't work together with OVN
distributed router.

Proposed Change
===============

::

 +-------------+-------------------------------+----------+ provider
               |                               |               or
               |                               |             public
               |                               |             network
       +-------+---------+             +-------+--------+
       |                 |    Transit  |                |
       |                 |    Network  |   VPN Agent    |
       |   OVN           |-------------|   Namespace    |
       |   Distributed   |             |                |
       |   Router        |             |                |
       +-----------------+             +----------------+
               |
               |
               |
               |
               |
               |
               |
               |
               |
               |        private network
 +-------+------------------------+-------------------------+------+
         |                        |                         |
         |                        |                         |
    +----+---+                +---+---+                  +--+---+
    | VM1    |                | VM2   |                  | VM3  |
    |        |                |       |                  |      |
    +--------+                +-------+                  +------+
                            Figure 1

Add a new VPN agent to support VPN+OVN. Together with the new agent, changes
for VPNaaS plugin service driver are also needed. This will have no impact on
existing VPN solution. The existing VPN agent can still work with neutron l3
router.

Changes on neutron server
-------------------------

Block diagram:

::

        +------------------------------------------------------------------+
        |                                                                  |
        |                        Neutron Server                            |
        |                                                                  |
        +--------------+----------------------------------+----------------+
        |              |                                  |                |
        |              |           VPN plugin             |                |
        |              |                                  |                |
        +-----------+  |  +-----------------------------+ |  +-------------+
        ||          |  |  |                             | |  |   VPN      ||
        ||  OVN API <-----+    VPN service driver       +----> scheduler  ||
        ||          |  |  |                             | |  |            ||
        +-----------+  |  +----+--------------------+---+ |  +-------------+
        |              |       |                    |     |                |
        +--------------+----------------------------------+----------------+
                               |                    |
                               +                    +
                            RPC message          RPC message
                               +                    +
                               |                    |
                               |                    |
                       +-------v------+       +-----v-------+
                       |              |       |             |
                       |   VPN agent  +-+HA+--+   VPN agent |
                       |              |       |             |
                       +--------------+       +-------------+
                                    Figure 2


Above block diagram is same as current VPNaaS framework. The neutron server
side includes below components:
1. VPN plugin
2. VPN service driver
3. VPN agent scheduler

VPN plugin
++++++++++

Both VPN plugin and plugin service driver are configurable in neutron.conf and
neutron_vpnaas.conf. The main function of VPN plugin is to store the VPN's
configuration in VPN database, then it invokes the VPN service driver, this
part of code is common for all VPNaaS solutions. For VPN+OVN, there should be
no change for this part.

VPN service driver and Agent scheduler
++++++++++++++++++++++++++++++++++++++

The VPN service driver has different implementation for different VPNaaS
solutions. For VPN+OVN, the main function of VPN plugin service driver is to
send the RPC message to specified VPN agents. For VPN+neutron L3, the L3 plugin
will call the router scheduler to select the agent to host the router when the
router is created. But for OVN L3, since OVN L3 router is a distributed router,
it does not need the router scheduler. So the VPN plugin does not know where
the RPC message should be sent to.
One solution for this issue is OVN l3 plugin still invokes the router scheduler
to select agent and sends the router create/update RPC message to VPN agent.
But this solution has below problems:

1. It is not compatible with current OVN L3 plugin since it needs changes on
OVN L3 plugin
2. It needs to send all routers' RPC message to agent, even the VPN service is
not enabled on the router. This has performance issue with scalable network.

Another solution for this issue is to add a new scheduler for VPNaaS. The new
scheduler will check if an agent has been assigned for the VPN service when
the VPN plugin driver sends a RPC message. It will select agents for the VPN
service if there is no agent for it. The selection algorithm can be same as
neutron L3 router scheduler, so some part of the code of neutron l3 router
scheduler can be re-used. As with the router scheduler, a scheduler plugin is
provided to support different scheduling algorithms.

Transit network
+++++++++++++++

the Transit network is used to connect the OVN logical router and namespace.
This part is completely new. And the subnet of this network should be
configurable and default is 169.254.64.0/18 (link-local is proposed for
transit network now). The transit network are created when the first VPN
service of the router is created, and two kinds of ports in the transit
network are created to connect the namespace and OVN logical router.
1. Router port. It is a distributed router port and used to connect the
transit network and the OVN router.
2. Namespace port. It is in namespace and used to connect the transit network
and the namespace.

The VPN service driver will check if the transit network and ports are
created. And it will invoke networking_ovn.ovsdb.impl_idl_ovn APIs to create
OVN transit network and OVN ports if they are not existing.

Static Routes management
++++++++++++++++++++++++

There are static route entries to make sure the traffic flow from tenant
private network can reach the VPN namespace. This part is completely new.

The static route entries are:
1. On namespace:
prefix: tenant private network subnet, nexthop: the IP of the transit port
on OVN logical router
This route entry to make sure the traffic from VPN peer can reach to the OVN
router. It will be added by VPN agent on the namespace.

2. On the OVN logical router:
prefix: VPN connection peer subnet, nexthop: the IP of the transit port on
the namespace
This route entry to make sure the traffic from the local private can reach to
the namespace. VPN service driver will invoke
networking_ovn.ovsdb.impl_idl_ovn APIs to add it when a new IPsec connection
is created or updated.

For other uses of VPN service driver, it will be same as existing plugin
service driver. The new VPNaaS plugin service driver only sends out below RPC
messages,
1. vpnservice_updated (existed) - create and delete messages are included in
updated message.


Changes on VPN agent
--------------------

Block diagram of vpn agent:

::

                               +--------------+
                      +--------+Public Network+------+
                      |        +--------------+      |
                      |                              |
                      |                              |
                      |                              |
                +-----+-----------+        +---------+-------+
                | Agent1 namespace|        | Agent2 namespace|
                | +-------------+ |        | +-------------+ |
                | |IPsec Process| +--VRRP--+ |IPsec Process| |
                | +-------------+ |        | +-------------+ |
                +-----------------+        +-----------------+
                      |                              |
                      |                              |
                      |                              |
                      |        +----------------+    |
                      +--------+Transit Network +----+
                               +-------+--------+
                                       |
                                       |
                                       |
                               +-------+--------+
                       +-------+   OVN Router   +----+
                       |       +----------------+    |
                       |                             |
                       |                             |
                 +-----+-----------+        +--------+--------+
                 | Private Network1|        |Private Network2 |
                 +-----+-----------+        +--------+--------+
                       |                             |
                       |                             |
                       |                             |
                 +-----+-----------+        +--------+--------+
                 |       VM1       |        |       VM2       |
                 +-----------------+        +-----------------+
                                    Figure 3

Namespace management
++++++++++++++++++++

There will be one namespace per VPN agent router. The Swan and VRRP processes
will be running in the same namespace. Currently, the router namespace is
created when the agent receives RPC message of the router creation from neutron
L3 plugin. But as discussed above, the OVN L3 plugin does not send RPC message
of router creation any more. The original L3 namespace management code will not
work. The new VPN agent needs to check if the namespace exists when it receives
the vpnservice_updated RPC message and create a new one if it does not exist.
With L3 agent, the namespace is removed when the routers is deleted. But for
VPN+OVN, the namespace will be removed when the VPN services are deleted from
the namespace.

Actually, the L3 agent does not only create the namespace, it also maintains a
router object. L3 agent manages the IPtables also via the router object. The
VPN agent stores the router object in an array via neutron callback mechanism
because VPN agent also needs to add IPtables NAT rules via the router object.
Now with OVN, the VPN agent needs to maintain the router object by itself since
there is no router creation RPC message any more. This part of code can be
re-used from L3 agent but many code changes are needed.

Transit network and port
++++++++++++++++++++++++

As mentioned in previous, there is a port in the namespace to connect transit
network, it is create by the VPN service driver. When the agent create the new
namespace, the agent will invoke the OVS interface driver to plug this port
also.

Static Routes management
++++++++++++++++++++++++

As mentioned in previous, there are some routes in the namespace to redirect
the traffic from peer to the OVN router. The agent will add/update these
routes when a new connection is created or updated.

VPN External IP address management
++++++++++++++++++++++++++++++++++

Within the neutron L3 router, VPNaaS currently shares router gateway public IP
address with router SNAT. But for VPN+OVN, the gateway public IP address can't
be shared with SNAT because SNAT is not in the namespace context. A new public
IP address is needed for the VPNaaS namespace. The namespace will request a
public IP address from neutron in the same provider/public network as the OVN
router and use that as public IP address for namespace. A validation will be
added in VPN plugin driver to check if the public IP address is assigned when
the VPN service is configured. An error message will be prompted if there is no
public IP address.

The neutron router resource will be extended to configure the VPN gateway
Public IP address. The extension is as below:
URL: /v2.0/routers/{router_id}
Request Example:

.. code-block:: javascript

    {
        "router": {
            "external_vpn_gateway_info": {
                "network_id": "8ca37218-28ff-41cb-9b10-039601ea7e6b"
            }
        }
    }

Response Example:

.. code-block:: javascript

    {
        "router": {
            "external_vpn_gateway_info": {
                "network_id": "8ca37218-28ff-41cb-9b10-039601ea7e6b",
                "external_fixed_ips": [
                    {
                        "subnet_id": "255.255.255.0",
                        "ip": "129.8.10.1"
                    }
                ]
            }
        }
    }

When user uses above API to create or update the router's VPN public IP
address. A neutron port will be created also in the external network. And the
agent will plug the external port also when the namespace is created and
unplug it when the namespace is deleted.

Heartbeat of the VPN agent
++++++++++++++++++++++++++

Currently, VPN agent is using L3 agent heartbeat since it inherits the L3 agent
code. But for VPN+OVN, the VPN agent does not inherit the L3 agent code any
more. So the heartbeat code should be leveraged from L3 agent to fit for the
new VPN agent.

Responsibility of DB operations
-------------------------------

The VPN service plugin will remain responsible for the CRUD operations on the
VPN DB objects. This will ensure consistency across common fields between
different VPN plugin.

Data Model Impact
+++++++++++++++++

An new VPN external gateway table will be added in VPN database to store the
VPN public IP address. And relationship is created also between this tables
and router table.
This table will be defined as below:

.. code-block:: python

    class VPNEXTGWInfo(model_base.BASEV2):
        __tablename__ = 'vpn_ext_gws'
        router_id = sa.Column(
            sa.String(36),
            sa.ForeignKey('routers.id', ondelete="CASCADE"),
            primary_key=True)
        port_id = sa.Column(
            sa.String(36),
            sa.ForeignKey('ports.id', ondelete="CASCADE"),
            primary_key=True)
        port = orm.relationship(models_v2.Port, lazy='joined')
        router = orm.relationship(l3_db.Router,
                                  backref=orm.backref(VPN_GW,
                                                      uselist=False,
                                                      lazy='joined',
                                                      cascade='delete'))

No other modifications to the existing tables are required (Need more
discussion for compatibility).

REST API and CLI Impact
+++++++++++++++++++++++

All VPN APIs will be kept same as current implementation. But as mentioned as
above, the router resource API will be extended to configure the VPN public IP
address. And the according CLI will be added also.

New configuration option
------------------------

A new configuration parameters are added in neutron-vpnaas.conf

* vpn_transit_net_cidr = 169.254.64.0/18

HA support
----------

The HA function is same as it is done currently L3 HA. But the VRRP protocol
is run on the VPN transit network. No extra HA network is needed.

Work Items
----------

* Add new VPN scheduler in the VPNaaS plugin RPC notification
* Add new namespace management in VPN agent side
* Add transit network management in VPN agent side
* Add transit routes management in VPN agent side
* Add VPN GW IP address support in both VPN plugin side and VPN agent side
* Add external VPN gateway DB model
* Add HA support on the agent side
* Add VPN metering function in VPN agent side

References
==========

.. _rfe: https://bugs.launchpad.net/neutron/+bug/1586253
