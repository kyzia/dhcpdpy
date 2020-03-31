dhcpdpy

Main code base was taken from: https://github.com/eblot/pybootd

=======

Main features:
- Takes IP and MAC addresses from MongoDB (or any other backend via http API)
- Works under Load Balancers (you can launch any number of instances per interface)
- Knows about ipxe and pxelinux
