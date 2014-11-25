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

logging = common.logging
common = common.Common()


def main():
  logging.basicConfig(level=logging.DEBUG if common.LISTEN_VERBOSE > 0 else logging.WARNING,
                      format='%(levelname)s - %(asctime)s %(message)s',
                      datefmt='[%b %d %H:%M:%S]')
  encrypt.init_table(common.SOCKS5_PASSWORD, common.SOCKS5_ENCRYPT_METHOD)
  config = common.get_config()

  tcp_servers = []
  udp_servers = []
  dns_resolver = asyncdns.DNSResolver()

  # may support multi port
  tcp_servers.append(tcprelay.TCPRelay(config, dns_resolver, False))
  udp_servers.append(udprelay.UDPRelay(config, dns_resolver, False))

  def run_server():
    def child_handler(signum, _):
      logging.warn('received SIGQUIT, doing graceful shutting down..')
      list(map(lambda s: s.close(next_tick=True),
               tcp_servers + udp_servers))
    signal.signal(signal.SIGQUIT, child_handler)
    try:
      loop = eventloop.EventLoop()
      dns_resolver.add_to_loop(loop)
      list(map(lambda s: s.add_to_loop(loop), tcp_servers + udp_servers))
      loop.run()
    except KeyboardInterrupt:
      os._exit(1)
    except (IOError, OSError) as e:
      logging.error(e)
      if config['verbose']:
        import traceback
        traceback.print_exc()
      os._exit(1)

  if int(config['workers']) > 1:
    if os.name == 'posix':
      children = []
      is_child = False
      for i in range(0, int(config['workers'])):
        r = os.fork()
        if r == 0:
          logging.info('worker started')
          is_child = True
          run_server()
          break
        else:
          children.append(r)
      if not is_child:
        def handler(signum, _):
          for pid in children:
            try:
              os.kill(pid, signum)
            except OSError:  # child may already exited
              pass
          sys.exit()
        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGQUIT, handler)

        # master
        for a_tcp_server in tcp_servers:
          a_tcp_server.close()
        for a_udp_server in udp_servers:
          a_udp_server.close()
        dns_resolver.close()

        for child in children:
          os.waitpid(child, 0)
    else:
      logging.warn('worker is only available on Unix/Linux')
      run_server()
  else:
    run_server()


if __name__ == '__main__':
  os.chdir(os.path.dirname(__file__) or '.')
  sys.exit(main())


