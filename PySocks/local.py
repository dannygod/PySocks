#!/usr/bin/env python
# coding:utf-8

# Copyright (c) 2014 clowwindy modified by dannygod
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

import common
import logging
import os
import select
import socket
import SocketServer
import sys
from protocol import socks5
from util import logging_utils
try:
  import gevent
  import gevent.monkey
  gevent.monkey.patch_all(dns=gevent.version_info[0] >= 1)
except ImportError:
  gevent = None
  sys.stdout.write('warning: gevent not found, using threading instead')
try:
  import encrypt
except ImportError:
  sys.path.append(os.path.join(os.path.dirname(sys.argv[0])))
  import encrypt
try:
  import ctypes
except ImportError:
  ctypes = None

SCRIPT_FILE = None

logging = sys.modules['logging'] = logging_utils.Logging('logging')
common = common.Common()


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
  allow_reuse_address = False

  def get_request(self):
    connection = self.socket.accept()
    connection[0].settimeout(common.TIMEOUT)
    return connection


class Socks5Server(SocketServer.StreamRequestHandler):
  @staticmethod
  def handle_tcp(sock, remote, encryptor, pending_data=None):
    try:
      fdset = [sock, remote]
      while True:
        should_break = False
        r, w, e = select.select(fdset, [], [], common.TIMEOUT)

        if not r:
          logging.warn('read time out')
          break

        # see local socket
        if sock in r:
          # prepare data to send.
          data = sock.recv(4096)
          if pending_data:
            data = pending_data + data
            pending_data = None

          # encrypt data
          data = encryptor.encrypt(data)
          if len(data) <= 0:
            should_break = True
          else:
            result = send_all(remote, data)
            if result < len(data):
              raise Exception('failed to send all data to local')

        # see remote socket
        if remote in r:
          data = encryptor.decrypt(remote.recv(4096))
          if len(data) <= 0:
            should_break = True
          else:
            result = send_all(sock, data)
            if result < len(data):
              raise Exception('failed to send all data to remote')

        if should_break:
          # make sure all data are read before we close the sockets
          # TODO: we haven't read ALL the data, actually
          # http://cs.ecs.baylor.edu/~donahoo/practical/CSockets/TCPRST.pdf
          break

    finally:
      sock.close()
      remote.close()

  # Override for StreamRequestHandler.handle()
  def setup(self):
    SocketServer.StreamRequestHandler.setup(self)
    self.encryptor = encrypt.Encryptor(common.SOCKS5_PASSWORD,
                                       common.SOCKS5_ENCRYPT_METHOD)

  # Override for BaseRequestHandler.handle()
  def handle(self):
    try:
      sock = self.connection
      sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

      data = sock.recv(262)
      client_req_method = socks5.getClientRequestMethod(data)

      if client_req_method == socks5.SOCKS5_METHOD_NO_AUTH:
        sock.send(socks5.responseMethodToClient(socks5.SOCKS5_METHOD_NO_AUTH))
      else:
        logging.error('unsupported method %d' % client_req_method)
        return

      (cmd, addrtype, addr_to_send,
       addr, port) = socks5.parseClientRequest(self.rfile)

      if not cmd:
        logging.error('unsupported cmd')
        return
      elif not addrtype:
        logging.error('unsupported addr type')
        return
      else:
        try:
          reply = socks5.replyClientRequest()
          self.wfile.write(reply)
          # reply immediately
          logging.info('connecting %s:%d' % (addr, port))
          remote = socket.create_connection((common.SOCKS5_SERVER,
                                             common.SOCKS5_SERVER_PORT),
                                            timeout=common.TIMEOUT)
          remote.settimeout(common.TIMEOUT)
          remote.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

          Socks5Server.handle_tcp(sock, remote, self.encryptor, addr_to_send)
        except (OSError, IOError, socket.timeout) as e:
          logging.error('Error[%s] %s' % (addr, e))
          return

    except (OSError, IOError, socket.timeout) as e:
      logging.error('Errors[%s] %s' % (addr, e))
      raise e


def pre_start():
  if sys.platform == 'cygwin':
    logging.critical('cygwin platform is not supported, \
                     please download `http://www.python.org/getit/`')
    sys.exit(-1)
  if ctypes and os.name == 'nt':
    ctypes.windll.kernel32.SetConsoleTitleW(u'ShadowSocks v%s' % common.VERSION)
    if not common.LISTEN_VISIBLE:
      ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(),
                                      0)
    else:
      ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(),
                                      1)
    
    blacklist = {
                    # http://s.weibo.com/weibo/goagent%2520360%2520%25E5%258D%25B8%25E8%25BD%25BD
                    '360safe' : False, 
                    # http://s.weibo.com/weibo/goagent%2520qqprotect
                    'QQProtect' : False, 
                }
    softwares = [k for k,v in blacklist.items() if v]
    if softwares:
      tasklist = os.popen('tasklist').read().lower()
      softwares = [x for x in softwares if x.lower()in tasklist]
      if softwares:
        error = u'某些安全软件(如 %s)可能和本软件存在冲突，\
            造成 CPU 占用过高。\n如有此现象建议暂时退出此安全\
            软件来继续运行PySocks' % ','.join(softwares)
        ctypes.windll.user32.MessageBoxW(None, error, u'PySocks 建议', 0)


def main():
  global SCRIPT_FILE
  SCRIPT_FILE = os.path.abspath(__file__)
  if os.path.islink(SCRIPT_FILE):
    SCRIPT_FILE = getattr(os, 'readlink', lambda x:x)(SCRIPT_FILE)
  os.chdir(os.path.dirname(os.path.abspath(SCRIPT_FILE)))

  logging.basicConfig(level=logging.DEBUG if common.LISTEN_DEBUGINFO else logging.INFO,
                      format='%(levelname)s - %(asctime)s %(message)s',
                      datefmt='[%b %d %H:%M:%S]')

  pre_start()
  sys.stdout.write(common.info())

  encrypt.init_table(common.SOCKS5_PASSWORD, common.SOCKS5_ENCRYPT_METHOD)

  try:
    # not support ipv6 now.
    #if IPv6:
    #    ThreadingTCPServer.address_family = socket.AF_INET6
    server = ThreadingTCPServer((common.LISTEN_IP, common.LISTEN_PORT), Socks5Server)
    server.timeout = common.TIMEOUT
    logging.info('starting local at %s:%d' % tuple(server.server_address[:2]))
    server.serve_forever()
  except Exception as e:
    logging.error('local server failed %s' % e)


if __name__ == '__main__':
  try:
    main()
  except KeyboardInterrupt:
    pass
  except Exception as e:
    if ctypes and os.name == 'nt':
      ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 1)
    raise
