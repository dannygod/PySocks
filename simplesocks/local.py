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
import os
import sys
import signal
import eventloop
import tcprelay
import udprelay
import asyncdns
from encrypt import encrypt
from protocol import socks5
try:
  import ctypes
except ImportError:
  ctypes = None


logging = common.logging
common = common.Common()


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
  SCRIPT_FILE = os.path.abspath(__file__)
  if os.path.islink(SCRIPT_FILE):
    SCRIPT_FILE = getattr(os, 'readlink', lambda x:x)(SCRIPT_FILE)
  os.chdir(os.path.dirname(os.path.abspath(SCRIPT_FILE)))

  logging.basicConfig(level=logging.DEBUG if common.LISTEN_VERBOSE else logging.INFO,
                      format='%(levelname)s - %(asctime)s %(message)s',
                      datefmt='[%b %d %H:%M:%S]')

  pre_start()
  sys.stdout.write(common.info())

  encrypt.init_table(common.SOCKS5_PASSWORD, common.SOCKS5_ENCRYPT_METHOD)
  config = common.get_config()

  try:
    logging.info('starting local at %s:%d' % (common.LISTEN_IP,
                                              common.LISTEN_PORT))
    dns_resolver = asyncdns.DNSResolver()
    tcp_server = tcprelay.TCPRelay(config, dns_resolver, True)
    udp_server = udprelay.UDPRelay(config, dns_resolver, True)
    loop = eventloop.EventLoop()
    dns_resolver.add_to_loop(loop)
    tcp_server.add_to_loop(loop)
    udp_server.add_to_loop(loop)

    def handler(signum, _):
      logging.warn('received SIGQUIT, doing graceful shutting down..')
      tcp_server.close(next_tick=True)
      udp_server.close(next_tick=True)
    signal.signal(signal.SIGTERM, handler)
    loop.run()

  except KeyboardInterrupt:
    raise
  except (IOError, OSError) as e:
    logging.error(str(e))
    if config['verbose']:
      import traceback
      traceback.print_exc()
    if ctypes and os.name == 'nt':
      ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(),
                                      1)
    raise


if __name__ == '__main__':
  sys.exit(main())
