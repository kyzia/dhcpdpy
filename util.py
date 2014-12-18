# -*- coding: utf-8 -*-

import re
import socket
import struct
import sys

def to_int(value):
    """Parse a string and convert it into a value"""
    if not value:
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, long):
        return int(value)
    mo = re.match('(?i)^\s*(\d+)\s*(?:([KM])B?)?\s*$', value)
    if mo:
        mult = { 'k': (1<<10), 'm': (1<<20) }
        value = int(mo.group(1))
        value *= mo.group(2) and mult[mo.group(2).lower()] or 1
        return value
    return int(value.strip(), value.startswith('0x') and 16 or 10)


def iptoint(ipstr):
    return struct.unpack('!I', socket.inet_aton(ipstr))[0]


def inttoip(ipval):
    return socket.inet_ntoa(struct.pack('!I', ipval))


def get_iface_config(address):
    if not address:
        return None
    try:
        import netifaces
    except ImportError:
        raise AssertionError("netifaces module is not installed")
    pool = iptoint(address)
    for iface in netifaces.interfaces():
        ifinfo = netifaces.ifaddresses(iface)
        if netifaces.AF_INET not in ifinfo:
            continue
        for inetinfo in netifaces.ifaddresses(iface)[netifaces.AF_INET]:
            addr = iptoint(inetinfo['addr'])
            mask = iptoint(inetinfo['netmask'])
            ip = addr & mask
            ip_client = pool & mask
            delta = ip ^ ip_client
            if not delta:
                config = { 'ifname': iface,
                           'server': inttoip(addr),
                           'net': inttoip(ip),
                           'mask': inttoip(mask) }
                return config
    return None


def hexline(data):
    """Convert a binary buffer into a hexadecimal representation"""
    LOGFILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or \
                       '.' for x in range(256)])
    src = ''.join(data)
    hexa = ' '.join(["%02x"%ord(x) for x in src])
    printable = src.translate(LOGFILTER)
    return "(%d) %s : %s" % (len(data), hexa, printable)
