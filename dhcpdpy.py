import time
import socket
import select

sock_list = []
host = "127.0.0.1"
port="1025"

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
    print "Sock: {0}".format(sock)
    print "Addr: {0}".format(addr)
    print "Data: {0}".format(data)