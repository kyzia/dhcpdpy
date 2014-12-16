import time
import socket
import select


from dhcpvars import *

sock_list = []
host = "127.0.0.1"
port = "1025"

def bind():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock_list.append(sock)
    sock.bind((host, int(port)))


def forever():
    while True:
        try:
            r,w,e = select.select(sock_list, [], sock_list)
            for sock in r:
                data, addr = sock.recvfrom(556)
                handle(sock, addr, data)
        except Exception, e:
            print "Exception {0}".format(e)
            time.sleep(1)

def handle(sock, addr, data):
    if len(data) < DHCPFormatSize:
            print 'Cannot be a DHCP or BOOTP request - too small!'
    tail = data[DHCPFormatSize:]
    buf = list(struct.unpack(DHCPFormat, data[:DHCPFormatSize]))
    print 'Tail: {0}'.format(tail)
    print 'Buffer: {0}'.format(buf)

    if buf[BOOTP_OP] != BOOTREQUEST:
        print 'Not a BOOTREQUEST'
        return
    options = parse_options(tail)
    if options is None:
        print 'Error in option parsing, ignore request'
        return


    print "Sock: {0}".format(sock)
    print "Addr: {0}".format(addr[0])
    #print "Port: {0}".format(addr[1])
    #print "Data: {0}".format(data)
    #sock_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #sock_s.sendto('Hello!', addr)

def parse_options(tail):
    print 'Parsing DHCP options'
    dhcp_tags = {}
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
            print "option %d: '%s', size:%d %s" % (tag, option, length, hexline(value))
        except KeyError:
            print "unknown option %d, size:%d %s:" % (tag, length, hexline(value))
            return None
        dhcp_tags[tag] = value

def hexline(data):
    """Convert a binary buffer into a hexadecimal representation"""
    LOGFILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or \
                       '.' for x in range(256)])
    src = ''.join(data)
    hexa = ' '.join(["%02x"%ord(x) for x in src])
    printable = src.translate(LOGFILTER)
    return "(%d) %s : %s" % (len(data), hexa, printable)

bind()
forever()