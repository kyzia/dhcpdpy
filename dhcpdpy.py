import time
import socket
import select
from binascii import hexlify

from util import hexline, iptoint, inttoip, get_iface_config

from dhcpvars import *

import logging

(ST_IDLE, ST_PXE, ST_DHCP) = range(3)


class DHCP:
    def __init__(self, logger):
        #internal params
        self.sock_list = []
        self.uuidpool = {}
        self.states = {}
        self.ippool = {}
        self.filepool = {}
        self.log = logger

        #self.log.info('Class initialized')

        #Server options
        self.server_config = self.get_srv_params()

    def get_srv_params(self):
        test_server_ip_address = "5.255.210.101"
        test_port = "67"
        return { 'ip_address': test_server_ip_address,
                 'port': int(test_port),
                 'mask': "255.255.255.0"
                }

    #Function return params for host by mac addr
    def get_host_params(self, mac_str):
        self.log.debug("Client mac is: {0}.".format(mac_str))

        # PXE options
        pxe_filename = 'lpxelinux.0'
        pxe_path = '/var/www/PXE'
        domain = 'local.ru'
        test_hostname = None

        if mac_str == "12:12:12:12:12:12":

            # Test host options
            test_hostname = "zverushko3.local.ru"
            #test_mac = "00:25:90:94:27:cc"
            test_ip = "100.100.100.101"
            test_gateway = "100.100.100.254"
            test_mask = "255.255.255.0"
            test_dns = '1.1.1.1'
            test_pxe_menu_http = 'http://local_server/PXE/'
 
            self.log.info("Request from {0} host.".format(test_hostname))

        if mac_str == "11:11:11:11:11:11":

            # Test host options
            test_hostname = "zverushko2.local.ru"
            #test_mac = "00:25:90:94:27:cc"
            test_ip = "101.101.101.102"
            test_gateway = "101.101.101.254"
            test_mask = "255.255.255.0"
            test_dns = '1.1.1.1'
            test_pxe_menu_http = 'http://local_server/PXE/'
 
            self.log.info("Request from {0} host.".format(test_hostname))


        if test_hostname:
            return { 'hostname': test_hostname,
                     'ip_address': test_ip,
                     'gateway': test_gateway,
                     'mask': test_mask,
                     'pxe_filename': pxe_filename,
                     'pxe_path': pxe_path,
                     'domain': domain,
                     'mac': mac_str,
                     'dns': test_dns,
                     'pxe_menu_http': test_pxe_menu_http,
                    }

        self.log.debug("Request from unknown host. Rejecting. Mac is:{0}".format(mac_str))

        return False

    def bind(self):
        self.log.info('Binding.')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock_list.append(sock)
        sock.bind((self.server_config['ip_address'], self.server_config['port']))

    def forever(self):
        while True:
            try:
                r,w,e = select.select(self.sock_list, [], self.sock_list)
                for sock in r:
                    data, req_addr = sock.recvfrom(556)
                    self.handle(sock, req_addr, data)
            except KeyError as e:
#            except Exception as e:
#                self.log.info("Socket buffer now: {0}".format(type(r)))
#                self.log.info("Exception {0}".format(e))
                time.sleep(1)

    def handle(self, sock, req_addr, data):

        tail = data[DHCPFormatSize:]
        buf = list(struct.unpack(DHCPFormat, data[:DHCPFormatSize]))
        options = self.parse_options(tail)

        # Get client mac address
        mac_str = self.get_mac_from_buf(buf)

        # Drop invalid request
        if not self.deny_wrong_request(data, buf, options):
            self.log.debug("Drop wrong request")
            return

        # Get all client host params by mac
        host_params = self.get_host_params(mac_str)
        self.log.debug("Host params: {0}. Mac: {1} ".format(host_params, mac_str))
        # If we cannot find host by mac in request - do not reply to client
        if not host_params:
            return

        dhcp_msg_type = self.get_dhcp_type(options)
        state = self.load_data(options, host_params, dhcp_msg_type)

        if not state:
            return

        pkt = self.construct_reply(buf, host_params, state, req_addr, options, dhcp_msg_type)

        self.answer_to_client(pkt=pkt, req_addr=req_addr, sock=sock)


    def load_data(self, options, host_params, dhcp_msg_type):
        if 97 in options and len(options[97]) == 17:
            uuid = options[97][1:]
            pxe = True
            self.log.info("PXE UUID has been received")
        else:
        #    uuid = self.uuidpool.get(host_params['mac'], None)
            uuid = None
            pxe = False
            self.log.info("PXE UUID not present in request")

        uuid_str = uuid and ('%s-%s-%s-%s-%s' % \
            tuple([hexlify(x) for x in uuid[0:4], uuid[4:6], uuid[6:8],
                                           uuid[8:10], uuid[10:16]])).upper()
        if uuid_str:
            self.log.info("UUID is %s for MAC %s" % (uuid_str, host_params['mac']))

        # Basic state machine
        currentstate = self.states.setdefault(host_params['mac'], ST_IDLE)
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
            self.log.info("Request from %s ignored (idle state). Simple dhcp." % host_params['mac'])
#            simple_dhcp = True
#            if not simple_dhcp:
#                return False
            return True

        return newstate

    def construct_reply(self, buf, host_params, state, req_addr, options, dhcp_msg_type):

        buf[BOOTP_OP] = BOOTREPLY
        self.log.info("Client IP: %s" % socket.inet_ntoa(buf[7]))
        self.log.info("BOOTP_CIADDR %r" % buf[BOOTP_CIADDR])

        if buf[BOOTP_CIADDR] == '\x00\x00\x00\x00':
            self.log.info("Client needs its address")

        self.log.info("Server netconfig is: {0}".format(self.server_config))

        mask = iptoint(self.server_config['mask'])
        reply_broadcast = iptoint(host_params['ip_address']) & mask
        reply_broadcast |= (~mask)&((1<<32)-1)
        buf[BOOTP_YIADDR] = socket.inet_aton(host_params['ip_address'])
        buf[BOOTP_SECS] = 0
        buf[BOOTP_FLAGS] = BOOTP_FLAGS_NONE

        req_addr = (req_addr[0], req_addr[1])

        self.log.info("Reply to: %s:%s" % req_addr)
        self.log.info("Options: {0}".format(options))

        #buf[BOOTP_SIADDR] = buf[BOOTP_GIADDR] = socket.inet_aton(self.server_config['ip_address'])
        buf[BOOTP_SIADDR] = socket.inet_aton(self.server_config['ip_address'])
        self.log.info("req_addr is: {0}".format(req_addr[0]))
        buf[BOOTP_GIADDR] = socket.inet_aton(req_addr[0])

        # sname
        buf[BOOTP_SNAME] = '.'.join(['unknown', 'localdomain'])
        # file
        buf[BOOTP_FILE] = host_params['pxe_filename']

        if not dhcp_msg_type:
            self.log.info("No DHCP message type found, discarding request")
            return
        if dhcp_msg_type == DHCP_DISCOVER:
            self.log.info("DHCP DISCOVER")
            dhcp_reply = DHCP_OFFER
            self.log.info("Offering lease for MAC %s: IP %s" % (host_params['mac'], host_params['ip_address']))
        elif dhcp_msg_type == DHCP_REQUEST:
            self.log.info("DHCP REQUEST")
            dhcp_reply = DHCP_ACK
            self.log.info("New lease for MAC %s: IP %s" % (host_params['mac'], host_params['ip_address']))
        elif dhcp_msg_type == DHCP_RELEASE:
            self.log.info("DHCP RELEASE")
    #        if not notify:
            return False
        elif dhcp_msg_type == DHCP_INFORM:
            self.log.info("DHCP INFORM")
            return False
        else:
            self.log.info("Unmanaged DHCP message: %d" % dhcp_msg_type)
            return

        # Store the filename
        if host_params['pxe_filename']:
            self.log.info("Filename for IP %s is '%s'" % (host_params['ip_address'], host_params['pxe_filename']))
            self.filepool[host_params['ip_address']] = host_params['pxe_filename']
        else:
            self.log.info("No filename defined for IP %s" % host_params['ip_address'])

        pkt = struct.pack(DHCPFormat, *buf)
        pkt += struct.pack('!BBB', DHCP_MSG, 1, dhcp_reply)

        server = socket.inet_aton(self.server_config['ip_address'])
        pkt += struct.pack('!BB4s', DHCP_SERVER, 4, server)

        pkt += struct.pack('!BBI', DHCP_LEASE_TIME, 4, int(str(28800)))

        mask = socket.inet_aton(host_params['mask'])
        pkt += struct.pack('!BB4s', DHCP_IP_MASK, 4, mask)

        gateway=socket.inet_aton(host_params['gateway'])
        pkt += struct.pack('!BB4s', DHCP_IP_GATEWAY, 4, gateway)

        dns = socket.inet_aton(host_params['dns'])
        pkt += struct.pack('!BB4s', DHCP_IP_DNS, 4, dns)

        pkt += struct.pack('!BB28s', DHCP_HOSTNAME, 28, host_params['hostname'])

        pkt += struct.pack('!BB9s', DHCP_DOMAIN, 9, host_params['domain'])

        pkt += struct.pack('!BB12s', DHCP_ROOT_PATH, 12, host_params['pxe_path'])

        reply_broadcast_ip = socket.inet_aton(inttoip(reply_broadcast))
        pkt += struct.pack('!BB4s', DHCP_BROADCAST_ADDR, 4, reply_broadcast_ip)

        pkt += struct.pack('!BBBB35s', DHCP_VENDOR_SPECIFIC, 37, 210, 35, host_params['pxe_menu_http'])

        pkt += struct.pack('!BBI', DHCP_RENEWAL_TIME, 4, int(str(14400)))

        pkt += struct.pack('!BBI', DHCP_REBINDING_TIME, 4, int(str(25200)))

        pkt += struct.pack('!BB4s', DHCP_UNASSIGNED, 4, server)

        pkt += struct.pack('!BB', DHCP_END, 0)

        #if pxe:
        #    self.uuidpool[mac_addr] = uuid

        return pkt

    def get_dhcp_type(self,options):
        # Extras (DHCP options)
        try:
            dhcp_msg_type = ord(options[53][0])
        except KeyError:
            dhcp_msg_type = None

        return dhcp_msg_type

    def answer_to_client(self, pkt, req_addr, sock):
        sock.sendto(pkt, req_addr)

    def deny_wrong_request(self, data, buf, options):

        if len(data) < DHCPFormatSize:
            self.log.info("Cannot be a DHCP or BOOTP request - too small!")
            return False

        if buf[BOOTP_OP] != BOOTREQUEST:
            self.log.info("Not a BOOTREQUEST")
            return False

        if options is None:
            self.log.info("Error in option parsing, ignore request")
            return False

        # Deny udhcp request - from ipmi through shared interface
        if options.get(60):
            if 'udhcp' in options.get(60):
                self.log.debug("Get option: {0} in option parsing, ignore request".format(options.get(60)))
                return False

        #self.log.info("Get option: {0} in option parsing. Contunue".format(options.get(60)))
        return True


    def get_mac_from_buf(self, buf):
        mac_addr = buf[BOOTP_CHADDR][:6]
        mac_str = ':'.join(['%02X' % ord(x) for x in mac_addr])
        return mac_str

    def parse_options(self, tail):
        #self.log.info("Parsing DHCP options")
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
                #self.log.info("option %d: '%s', size:%d %s" % (tag, option, length, hexline(value)))
            except KeyError:
                self.log.info("unknown option %d, size:%d %s:" % (tag, length, hexline(value)))
                return None
            dhcp_tags[tag] = value

        return dhcp_tags  

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger()

    logger.info('Start reading database')

    instance = DHCP(logger=logger)
    instance.bind()
    instance.forever()