dhcpdpy

Main code base taken from: https://github.com/eblot/pybootd

=======

Main concepts:
- take ip address from mongo db (or other backend) and reply to dhcp request
- can work over SLB (in different from isc-dhcp-server, udp sendto works from correct interface)
- not simply - knows about ipxe and pxelinux
