#!/usr/bin/env python
# coding:utf-8

# Copyright (c) 2012 clowwindy modified by dannygod
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import sys
import os
import socket
import select
import SocketServer
import struct
import logging
try:
    import gevent
    import gevent.monkey
    gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
    gevent = None
    sys.stdout.write('warning: gevent not found, using threading instead')
try:
    import encrypt
    import utils
except ImportError:
    sys.path.append(os.path.join(os.path.dirname(sys.argv[0])))
    import encrypt
    import utils

common = utils.Common()


def send_all(sock, data):
    bytes_sent = 0
    while True:
        r = sock.send(data[bytes_sent:])
        if r < 0:
            return r
        bytes_sent += r
        if bytes_sent == len(data):
            return bytes_sent


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    allow_reuse_address = True


class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    data = self.decrypt(sock.recv(4096))
                    if len(data) <= 0:
                        break
                    result = send_all(remote, data)
                    if result < len(data):
                        raise Exception('failed to send all data')
                if remote in r:
                    data = self.encrypt(remote.recv(4096))
                    if len(data) <= 0:
                        break
                    result = send_all(sock, data)
                    if result < len(data):
                        raise Exception('failed to send all data')

        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return self.encryptor.encrypt(data)

    def decrypt(self, data):
        return self.encryptor.decrypt(data)

    def handle(self):
        try:
            self.encryptor = encrypt.Encryptor(common.SOCKS5_PASSWORD, common.SOCKS5_ENCRYPT_METHOD)
            sock = self.connection
            iv_len = self.encryptor.iv_len()
            if iv_len:
                self.decrypt(sock.recv(iv_len))
            addrtype = ord(self.decrypt(sock.recv(1)))
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(self.rfile.read(4)))
            elif addrtype == 3:
                addr = self.decrypt(
                    self.rfile.read(ord(self.decrypt(sock.recv(1)))))
            elif addrtype == 4:
                addr = socket.inet_ntop(socket.AF_INET6,
                                        self.decrypt(self.rfile.read(16)))
            else:
                # not support
                logging.warn('addr_type not support')
                return
            port = struct.unpack('>H', self.decrypt(self.rfile.read(2)))
            try:
                logging.info('connecting %s:%d' % (addr, port[0]))
                remote = socket.create_connection((addr, port[0]))
            except socket.error, e:
                # Connection refused
                logging.warn(e)
                return
            self.handle_tcp(sock, remote)
        except socket.error, e:
            logging.warn(e)

def main():
    #logging.basicConfig(level=logging.DEBUG, format='%(asctime)s %(levelname)-8s %(message)s',
    #    datefmt='%Y-%m-%d %H:%M:%S', filemode='a+')
    encrypt.init_table(common.SOCKS5_PASSWORD, common.SOCKS5_ENCRYPT_METHOD)
    # not support ipv6 now.
    #if IPv6:
    #    ThreadingTCPServer.address_family = socket.AF_INET6
    try:
        server = ThreadingTCPServer((common.SOCKS5_SERVER, common.SOCKS5_SERVER_PORT), Socks5Server)
        logging.info("starting server at %s:%d" % tuple(server.server_address[:2]))
        server.serve_forever()
    except socket.error, e:
        logging.error(e)


if __name__ == '__main__':
    os.chdir(os.path.dirname(__file__) or '.')
    main()


