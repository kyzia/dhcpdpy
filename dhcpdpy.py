import time                                                                                                                                                   
import socket                                                                                                                                                 
import select                                                                                                                                                 
from binascii import hexlify                                                                                                                                  
                                                                                                                                                              
from util import hexline, iptoint, inttoip, get_iface_config                                                                                                  

from dhcpvars import *

(ST_IDLE, ST_PXE, ST_DHCP) = range(3)

#internal params
sock_list = []
uuidpool = {}
states = {}
ippool = {}
filepool = {}

#Server options
server_interface_ip = "5.255.210.101"
port = "67"

pxe_filename = 'lpxelinux.0'
pxe_path = '/var/www/PXE'
domain = 'localdomain.ru'

# Test host options
test_hostname = "zverushko2"
#test_mac = "00:25:90:94:27:cc"
test_mac = "00-25-90-94-27-CC"
test_ip = "100.100.100.100"
test_gateway = "100.100.100.254"
test_mask = "255.255.255.0"

def bind():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_list.append(sock)
    sock.bind((server_interface_ip, int(port)))


def forever():
    while True:
        try:
            r,w,e = select.select(sock_list, [], sock_list)
            for sock in r:
                data, addr = sock.recvfrom(556)
                handle(sock, addr, data)
        except Exception as e:
            print "Socket buffer now: {0}".format(type(r))
            print "Exception {0}".format(e)
            time.sleep(1)


def handle(sock, addr, data):
    if len(data) < DHCPFormatSize:
            print 'Cannot be a DHCP or BOOTP request - too small!'
    tail = data[DHCPFormatSize:]
    buf = list(struct.unpack(DHCPFormat, data[:DHCPFormatSize]))
    #print 'Tail: {0}'.format(tail)
    #print 'Buffer: {0}'.format(buf)

    if buf[BOOTP_OP] != BOOTREQUEST:
        print 'Not a BOOTREQUEST'
        return
    options = parse_options(tail)
    if options is None:
        print 'Error in option parsing, ignore request'
        return
    
    if options.get(60):
        if 'udhcp' in options.get(60):
            return

    # Extras (DHCP options)
    try:
        dhcp_msg_type = ord(options[53][0])
    except KeyError:
        dhcp_msg_type = None

    server_addr = server_interface_ip
    mac_addr = buf[BOOTP_CHADDR][:6]
    mac_str = '-'.join(['%02X' % ord(x) for x in mac_addr])

    if not mac_str == "00-25-90-94-27-CC":
       print "Unath access"
       return

    if 97 in options and len(options[97]) == 17:
        uuid = options[97][1:]
        pxe = True
        print 'PXE UUID has been received'
    else:
        uuid = uuidpool.get(mac_str, None)
        pxe = False
        print 'PXE UUID not present in request'

    uuid_str = uuid and ('%s-%s-%s-%s-%s' % \
        tuple([hexlify(x) for x in uuid[0:4], uuid[4:6], uuid[6:8],
                                       uuid[8:10], uuid[10:16]])).upper()
    if uuid_str:
        print 'UUID is %s for MAC %s' % (uuid_str, mac_str)

    hostname = ''
    filename = ''

    # Basic state machine
    currentstate = states.setdefault(mac_str, ST_IDLE)
    newstate = currentstate
    if currentstate == ST_IDLE:
        if pxe and (dhcp_msg_type == DHCP_DISCOVER):
            # BIOS is booting up, and try to locate a DHCP server
            newstate = ST_PXE
    elif currentstate == ST_PXE:
        if not pxe and (dhcp_msg_type == DHCP_REQUEST):
            # OS is booting up, and confirm a previous DHCP dicovery
            newstate = ST_DHCP
    else: # currentstate == ST_DHCP
        if pxe:
            # OS was running but the BIOS is performing a DHCP request:
            # board has been restarted
            newstate = ST_PXE

    # if the state has not evolved from idle, there is nothing to do
    if newstate == ST_IDLE:
        print "Request from %s ignored (idle state)" % mac_str
        sdhcp = 'allow_simple_dhcp'
        simple_dhcp = True
        if not simple_dhcp:
            return


    # construct reply
    buf[BOOTP_OP] = BOOTREPLY
    print "Client IP: %s" % socket.inet_ntoa(buf[7])
    print "BOOTP_CIADDR %r" % buf[BOOTP_CIADDR]


    if buf[BOOTP_CIADDR] == '\x00\x00\x00\x00':
        print "Client needs its address"
        if mac_str == test_mac:
            print "zverushko2 wants address"
            ip = test_ip

    netconfig = get_iface_config(server_interface_ip)
    print "Server netconfig is: {0}".format(netconfig)

    mask = iptoint(netconfig['mask'])
    reply_broadcast = iptoint(ip) & mask
    reply_broadcast |= (~mask)&((1<<32)-1)
    buf[BOOTP_YIADDR] = socket.inet_aton(ip)
    buf[BOOTP_SECS] = 0
    buf[BOOTP_FLAGS] = BOOTP_FLAGS_NONE
    
    addr = (addr[0], addr[1])

    print "Reply to: %s:%s" % addr
    print "Options: {0}".format(options)

    buf[BOOTP_SIADDR] = buf[BOOTP_GIADDR] = socket.inet_aton(server_addr)

    # sname
    buf[BOOTP_SNAME] = '.'.join(['unknown', 'localdomain'])
        # file
    buf[BOOTP_FILE] = pxe_filename

#    print 'Parsing DHCP options'
    print "Options: {0}".format(options)


    if not dhcp_msg_type:
        print "No DHCP message type found, discarding request"
        return
    if dhcp_msg_type == DHCP_DISCOVER:
        print "DHCP DISCOVER"
        dhcp_reply = DHCP_OFFER
        print "Offering lease for MAC %s: IP %s" % (mac_str, ip)
    elif dhcp_msg_type == DHCP_REQUEST:
        print "DHCP REQUEST"
        dhcp_reply = DHCP_ACK
        print "New lease for MAC %s: IP %s" % (mac_str, ip)
    elif dhcp_msg_type == DHCP_RELEASE:
        print "DHCP RELEASE"
#        if not notify:
        return
    elif dhcp_msg_type == DHCP_INFORM:
        print "DHCP INFORM"
        return
    else:
        print "Unmanaged DHCP message: %d" % dhcp_msg_type
        return

    # Store the filename
    if filename:
        print "Filename for IP %s is '%s'" % (ip, filename)
        filepool[ip] = filename
    else:
        print "No filename defined for IP %s" % ip

    pkt = struct.pack(DHCPFormat, *buf)
    pkt += struct.pack('!BBB', DHCP_MSG, 1, dhcp_reply)

    server = socket.inet_aton(server_addr)
    pkt += struct.pack('!BB4s', DHCP_SERVER, 4, server)

    pkt += struct.pack('!BBI', DHCP_LEASE_TIME, 4, int(str(28800)))

    mask = socket.inet_aton(test_mask)
    pkt += struct.pack('!BB4s', DHCP_IP_MASK, 4, mask)

    gateway=socket.inet_aton(test_gateway)
    pkt += struct.pack('!BB4s', DHCP_IP_GATEWAY, 4, gateway)

    dns = '141.8.146.1'
    dns = socket.inet_aton(dns)
    pkt += struct.pack('!BB4s', DHCP_IP_DNS, 4, dns)

    pkt += struct.pack('!BB28s', DHCP_HOSTNAME, 28, test_hostname)    

    pkt += struct.pack('!BB9s', DHCP_DOMAIN, 9, domain)    

    pkt += struct.pack('!BB12s', DHCP_ROOT_PATH, 12, pxe_path)

    pxe_menu_http = 'http://setup.local/PXE/'
    pkt += struct.pack('!BBBB35s', DHCP_VENDOR_SPECIFIC, 37, 210, 35, pxe_menu_http)

    pkt += struct.pack('!BB4s', DHCP_UNASSIGNED, 4, server)

    pkt += struct.pack('!BB', DHCP_END, 0)

#    if pxe:
#        extra_buf = build_pxe_options(options, server)
#        if not extra_buf:
#            return    
#    else:
#        extra_buf = build_dhcp_options(hostname)

    if pxe:
        uuidpool[mac_addr] = uuid

    # send the response
    #sock.sendto(pkt + extra_buf, addr)
    sock.sendto(pkt, addr)


def build_pxe_options(options, server):
    try:
        buf = ''
        uuid = options[97]
        buf += struct.pack('!BB%ds' % len(uuid),
                           97, len(uuid), uuid)
        clientclass = options[60]
        clientclass = clientclass[:clientclass.find(':')]
        buf += struct.pack('!BB%ds' % len(clientclass),
                           60, len(clientclass), clientclass)
        vendor = ''

        vendor += struct.pack('!BBB', PXE_DISCOVERY_CONTROL, 1, 0x0A)
        vendor += struct.pack('!BBHB4s', PXE_BOOT_SERVERS, 2+1+4,
                              0, 1, server)
        srvstr = 'dhcpdpy'
        vendor += struct.pack('!BBHB%ds' % len(srvstr), PXE_BOOT_MENU,
                              2+1+len(srvstr), 0, len(srvstr), srvstr)
        prompt = 'Stupid PXE'
        vendor += struct.pack('!BBB%ds' % len(prompt), PXE_MENU_PROMPT,
                              1+len(prompt), len(prompt), prompt)
        buf += struct.pack('!BB%ds' % len(vendor), 43,
                           len(vendor), vendor)
        buf += struct.pack('!BBB', 255, 0, 0)
        return buf
    except KeyError, e:
        print "Missing options, cancelling: {0}".format(str(e))
        return None

def parse_options(tail):
    #print 'Parsing DHCP options'
    dhcp_tags = {}
#    print tail
    while tail:
        tag = ord(tail[0])
        # padding
        if tag == 0:
            continue
        if tag == 0xff:
            return dhcp_tags
        length = ord(tail[1])
        (value, ) = struct.unpack('!%ss' % length, tail[2:2+length])
        tail = tail[2+length:]
        try:
            option = DHCP_OPTIONS[tag]
#            print "option %d: '%s', size:%d %s" % (tag, option, length, hexline(value))
        except KeyError:
            print "unknown option %d, size:%d %s:" % (tag, length, hexline(value))
            return None
        dhcp_tags[tag] = value


bind()
forever()