import struct

BOOTP_PORT_REQUEST = 67
BOOTP_PORT_REPLY = 68

BOOTREQUEST = 1
BOOTREPLY = 2

BOOTPFormat = '!4bIHH4s4s4s4s16s64s128s64s'
BOOTPFormatSize = struct.calcsize(BOOTPFormat)
DHCPFormat = '!4bIHH4s4s4s4s16s64s128s4s'
DHCPFormatSize = struct.calcsize(DHCPFormat)

(BOOTP_OP,BOOTP_HTYPE,BOOTP_HLEN,BOOTP_HOPS,BOOTP_XID,BOOTP_SECS,
 BOOTP_FLAGS,BOOTP_CIADDR,BOOTP_YIADDR,BOOTP_SIADDR,BOOTP_GIADDR,
 BOOTP_CHADDR,BOOTP_SNAME,BOOTP_FILE,BOOTP_VEND) = range(15)

BOOTP_FLAGS_NONE = 0
BOOTP_FLAGS_BROADCAST = 1<<15

COOKIE='\0x63\0x82\0x53\0x63'

DHCP_OPTIONS = {  0: 'Byte padding',
                  1: 'Subnet mask',
                  2: 'Time offset',
                  3: 'Routers',
                  4: 'Time servers',
                  5: 'Name servers',
                  6: 'Domain name servers',
                  7: 'Log servers',
                  8: 'Cookie servers',
                  9: 'Line printer servers',
                 10: 'Impress servers',
                 11: 'Resource location servers',
                 12: 'Host Name', # + PXE extensions
                 13: 'Boot file size',
                 14: 'Dump file',
                 15: 'Domain name',
                 16: 'Swap server',
                 17: 'Root path',
                 18: 'Extensions path',
                 # --- IP layer / host ---
                 19: 'IP forwarding',
                 20: 'Source routing',
                 21: 'Policy filter',
                 22: 'Maximum datagram reassembly size',
                 23: 'Default IP TTL',
                 24: 'Path MTU aging timeout',
                 25: 'Path MTU plateau table',
                 # --- IP Layer / interface ---
                 26: 'Interface MTU',
                 27: 'All subnets local',
                 28: 'Broadcast address',
                 29: 'Perform mask discovery',
                 30: 'Mask supplier',
                 31: 'Perform router discovery',
                 32: 'Router solicitation address',
                 33: 'Static route',
                 # --- Link layer ---
                 34: 'Trailer encapsulation',
                 35: 'ARP cache timeout',
                 36: 'Ethernet encaspulation',
                 # --- TCP ---
                 37: 'TCP default TTL',
                 38: 'TCP keepalive interval',
                 39: 'TCP keepalive garbage',
                 # --- Application & Services ---
                 40: 'Network Information Service domain',
                 41: 'Network Information servers',
                 42: 'Network Time Protocol servers',
                 43: 'Vendor specific',
                 44: 'NetBIOS over TCP/IP name server',
                 45: 'NetBIOS over TCP/IP datagram server',
                 46: 'NetBIOS over TCP/IP node type',
                 47: 'NetBIOS over TCP/IP scope',
                 48: 'X Window system font server',
                 49: 'X Window system display manager',
                 50: 'Requested IP address',
                 51: 'IP address lease time',
                 52: 'Option overload',
                 53: 'DHCP message',
                 54: 'Server ID',
                 55: 'Param request list',
                 56: 'Error message',
                 57: 'Message length',
                 58: 'Renewal time',
                 59: 'Rebinding time',
                 60: 'Class ID',
                 61: 'GUID',
                 64: 'Network Information Service+ domain',
                 65: 'Network Information Service+ servers',
                 66: 'TFTP server name',
                 67: 'Bootfile name',
                 68: 'Mobile IP home agent',
                 69: 'Simple Mail Transport Protocol servers',
                 70: 'Post Office Protocol servers',
                 71: 'Network News Transport Protocol servers',
                 72: 'World Wide Web servers',
                 73: 'Finger servers',
                 74: 'Internet Relay Chat server',
                 77: 'User Class Data',
                 93: 'System architecture',
                 94: 'Network type',
                 97: 'UUID/GUID-based Client Identifier',
                 175: 'encapsulate ipxe',
                 208: 'pxelinux.magic',
                 209: 'pxelinux.configfile',
                 210: 'pxelinux.pathprefix',
                 211: 'pxelinux.reboottime',
                 203: 'parentserv',
                 204: 'parentpath',
                 255: 'End of DHCP options' }

DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_DECLINE = 4
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7
DHCP_INFORM = 8
DHCP_RENEWING = 100

DHCP_IP_MASK = 1
DHCP_IP_GATEWAY = 3
DHCP_IP_DNS = 6
DHCP_HOSTNAME = 12
DHCP_DOMAIN = 15
DHCP_ROOT_PATH = 17
DHCP_LEASE_TIME = 51
DHCP_MSG = 53
DHCP_SERVER = 54
DHCP_VENDOR_SPECIFIC = 43
DHCP_PXELINUX_MAGIC = 208
DHCP_PXELINUX_CONFIGFILE = 209
DHCP_PXELINUX_PATHPREFIX = 210
DHCP_PXELINUX_REBOOTTIME = 211
DHCP_UNASSIGNED = 203
DHCP_END = 255

PXE_DISCOVERY_CONTROL = 6
DISCOVERY_MCAST_ADDR = 7
PXE_BOOT_SERVERS = 8
PXE_BOOT_MENU = 9
PXE_MENU_PROMPT = 10
