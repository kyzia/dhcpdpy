dhcpdpy

Main code base taken from: https://github.com/eblot/pybootd

=======

Main concepts:
- take ip address/hostname/mask/broadcast/gateway from http api (or other backend) and reply to dhcp request
- can work over SLB (in different from isc-dhcp-server, udp sendto works from correct interface)
- simply
- knows about ipxe and pxelinux
