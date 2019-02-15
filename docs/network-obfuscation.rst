===============================
Network Obfuscation Information
===============================

Network Obfuscation Overview
-----------------------------

Beginning with version 0.3.0, soscleaner uses the ipaddr module to manage network objects and their obfuscation
This will let the program be much more intelligent with how it obfuscates the data while being network away, etc.

IPv4 Network database
----------------------

Each entry in ``self.net_db`` represents a network and its obfuscated value. ``self.net_db`` is a list of tuples. Each tuple has the following format::

    (original_network, obfuscated_network)

For each entry in ``self.net_db``, ``x[0]`` is the original network as an ``ipaddr.IPv4Network`` object
and ``x[1]`` is the obfuscated network as an ``ipaddr.IPv4Network`` object.

IPv4 database
--------------

Each entry in ``self.ip_db`` represents a found IP address and its obfuscated value

When ``self.clean_report is run``, it populates ``self.net_db`` with the networks found in an sosreports routing table as well as with any networks specified using the ``-n`` command line parameter.

Each time an IP is matched against, it will be compared against the values in net_db to see which network it is member to.
The IP is then obfuscated sanely with fidelity to the subnet and relative network space.

If an IP address is matched that doesn't exist in any other, it will be obfuscated with a 'default' Network defined as self.default_net.
self.default_net is also used to begin incrementing for each obfuscated network

There is also a metadata dictionary for the obfuscated networks. It tracks the number of used hosts so the obfuscated networks can be iterated cleanly.
This is self.net_metadata. The keys are set when the networks are defined.
Current Values:
host_count - used to give out the next obfuscated IP address

The length of the dictionary is also used to determine how many obfuscated networks are in use.

Assumptions made:
if you use larger subnets than a /8, you will break the math for creating obfuscating networks.
Why?
To calculate the next obfuscation subnet, I have no idea what the next subnet mask will be, and I don't want to get into crazy CIDR calculations.
SO
I take the default_net's first octet, increment it by the current existing obfuscated networks, and create a subnet with the corresponding subnet mask.
So the obfuscated network map could end up like:
128.0.0.0/8  - default_net
129.0.0.0/24 - an obfuscated network
130.0.0.0/16 - network 2
131.0.0.0/30 - network 3
132.0.0.0/8  - network 4
133.0.0.0/32 - network 5

Essentially I'm burning a lot of IP addresses to keep the math simple. The default network starts 1 above the loopback, so we don't have to account for that.
I know there are corner cases here that could break the math. I have to hope common sense will prevail... -jduncan
