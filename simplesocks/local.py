#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2012-2015 clowwindy modified by dannygod
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from __future__ import absolute_import, division, print_function, \
    with_statement

import __init__
import os
import sys
import signal
try:
  import ctypes
except ImportError:
  ctypes = None

from simplesocks import common, eventloop, tcprelay, udprelay, asyncdns
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

  config = common.get_config()
  if config.has_key('port_password') and config['port_password']:
    if config.has_key('password') and config['password']:
      logging.warn('warning: port_password should not be used with '
                   'server_port and password. server_port and password '
                   'will be ignored')
    config['password'] = config['port_password'][common.SOCKS5_SERVER_PORT]
  config['server_port'] = common.SOCKS5_SERVER_PORT

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
    signal.signal(getattr(signal, 'SIGQUIT', signal.SIGTERM), handler)

    def int_handler(signum, _):
      sys.exit(1)
    signal.signal(signal.SIGINT, int_handler)

    loop.run()
  except KeyboardInterrupt:
    raise
  except Exception as e:
    logging.exception(e, verbose=config['verbose'])
    if ctypes and os.name == 'nt':
      ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(),
                                      1)
    raise


if __name__ == '__main__':
  sys.exit(main())
