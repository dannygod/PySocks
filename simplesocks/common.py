#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 dannygod

from __future__ import absolute_import, division, print_function, \
    with_statement

import os
import socket
import struct
import sys
from util import value_utils
from util import logging_utils

logging = sys.modules['logging'] = logging_utils.Logging('logging')

__version__ = '3.0.0'


class Common(object):
  """Global Config Object"""

  def __init__(self):
    """load config from config"""
    config_path = os.path.join(os.path.dirname(__file__), os.pardir, 'config')
    self.CONFIG = value_utils.ReadPyValues(config_path)

    # listen
    self.LISTEN_IP = self.CONFIG['local']
    self.LISTEN_PORT = self.CONFIG['local_port']
    self.LISTEN_VISIBLE = self.CONFIG['visible']
    self.LISTEN_VERBOSE = self.CONFIG['verbose'] if self.CONFIG.has_key('verbose') else 0

    # server info
    self.SOCKS5_SERVER = self.CONFIG['server']
    self.SOCKS5_SERVER_PORT = self.CONFIG['server_port']
    self.SOCKS5_PASSWORD = self.CONFIG['password']
    self.SOCKS5_ENCRYPT_METHOD = self.CONFIG['method']

    self.TIMEOUT = self.CONFIG['timeout']

    # app version
    self.VERSION = __version__

  def info(self):
    info = ''
    info += '------------------------------------------------------\n'
    info += 'SimpleSocks Version    : %s (python/%s)\n' % (self.VERSION, sys.version.partition(' ')[0])
    info += 'Listen Address         : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
    info += 'Verbose                : %s\n' % self.LISTEN_VERBOSE if self.LISTEN_VERBOSE else ''
    info += 'SOCKS5 Server          : %s:%d\n' % (self.SOCKS5_SERVER, self.SOCKS5_SERVER_PORT)
    info += 'TimeOut                : %d\n' % self.TIMEOUT
    info += '------------------------------------------------------\n'
    return info

  def get_config(self):
    return self.CONFIG


def compat_ord(s):
  if type(s) == int:
    return s
  return _ord(s)


def compat_chr(d):
  if bytes == str:
    return _chr(d)
  return bytes([d])


_ord = ord
_chr = chr
ord = compat_ord
chr = compat_chr


def to_bytes(s):
  if bytes != str:
    if type(s) == str:
      return s.encode('utf-8')
  return s


def to_str(s):
  if bytes != str:
    if type(s) == bytes:
      return s.decode('utf-8')
  return s


def inet_ntop(family, ipstr):
  if family == socket.AF_INET:
    return to_bytes(socket.inet_ntoa(ipstr))
  elif family == socket.AF_INET6:
    import re
    v6addr = ':'.join(('%02X%02X' % (ord(i), ord(j))).lstrip('0')
                      for i, j in zip(ipstr[::2], ipstr[1::2]))
    v6addr = re.sub('::+', '::', v6addr, count=1)
    return to_bytes(v6addr)


def inet_pton(family, addr):
  addr = to_str(addr)
  if family == socket.AF_INET:
    return socket.inet_aton(addr)
  elif family == socket.AF_INET6:
    if '.' in addr:  # a v4 addr
      v4addr = addr[addr.rindex(':') + 1:]
      v4addr = socket.inet_aton(v4addr)
      v4addr = map(lambda x: ('%02X' % ord(x)), v4addr)
      v4addr.insert(2, ':')
      newaddr = addr[:addr.rindex(':') + 1] + ''.join(v4addr)
      return inet_pton(family, newaddr)
    dbyts = [0] * 8  # 8 groups
    grps = addr.split(':')
    for i, v in enumerate(grps):
      if v:
        dbyts[i] = int(v, 16)
      else:
        for j, w in enumerate(grps[::-1]):
          if w:
            dbyts[7 - j] = int(w, 16)
          else:
            break
        break
    return b''.join((chr(i // 256) + chr(i % 256)) for i in dbyts)
  else:
    raise RuntimeError("What family?")


def patch_socket():
  if not hasattr(socket, 'inet_pton'):
    socket.inet_pton = inet_pton
  
  if not hasattr(socket, 'inet_ntop'):
    socket.inet_ntop = inet_ntop


patch_socket()


ADDRTYPE_IPV4 = 1
ADDRTYPE_IPV6 = 4
ADDRTYPE_HOST = 3


def pack_addr(address):
  address_str = to_str(address)
  for family in (socket.AF_INET, socket.AF_INET6):
    try:
      r = socket.inet_pton(family, address_str)
      if family == socket.AF_INET6:
        return b'\x04' + r
      else:
        return b'\x01' + r
    except (TypeError, ValueError, OSError, IOError):
      pass
  if len(address) > 255:
    address = address[:255]  # TODO
  return b'\x03' + chr(len(address)) + address


def parse_header(data):
  addrtype = ord(data[0])
  dest_addr = None
  dest_port = None
  header_length = 0
  if addrtype == ADDRTYPE_IPV4:
    if len(data) >= 7:
      dest_addr = socket.inet_ntoa(data[1:5])
      dest_port = struct.unpack('>H', data[5:7])[0]
      header_length = 7
    else:
      logging.warn('header is too short')
  elif addrtype == ADDRTYPE_HOST:
    if len(data) > 2:
      addrlen = ord(data[1])
      if len(data) >= 2 + addrlen:
        dest_addr = data[2:2 + addrlen]
        dest_port = struct.unpack('>H', data[2 + addrlen:4 +
                                  addrlen])[0]
        header_length = 4 + addrlen
      else:
        logging.warn('header is too short')
    else:
      logging.warn('header is too short')
  elif addrtype == ADDRTYPE_IPV6:
    if len(data) >= 19:
      dest_addr = socket.inet_ntop(socket.AF_INET6, data[1:17])
      dest_port = struct.unpack('>H', data[17:19])[0]
      header_length = 19
    else:
      logging.warn('header is too short')
  else:
    logging.warn('unsupported addrtype %d, maybe wrong password' %
                   addrtype)
  if dest_addr is None:
    return None
  return addrtype, to_bytes(dest_addr), dest_port, header_length


def test_inet_conv():
  ipv4 = b'8.8.4.4'
  b = inet_pton(socket.AF_INET, ipv4)
  assert inet_ntop(socket.AF_INET, b) == ipv4
  ipv6 = b'2404:6800:4005:805::1011'
  b = inet_pton(socket.AF_INET6, ipv6)
  assert inet_ntop(socket.AF_INET6, b) == ipv6


def test_parse_header():
  assert parse_header(b'\x03\x0ewww.google.com\x00\x50') == \
    (3, b'www.google.com', 80, 18)
  assert parse_header(b'\x01\x08\x08\x08\x08\x00\x35') == \
    (1, b'8.8.8.8', 53, 7)
  assert parse_header((b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00'
                       b'\x00\x10\x11\x00\x50')) == \
    (4, b'2404:6800:4005:805::1011', 80, 19)


def test_pack_header():
  assert pack_addr(b'8.8.8.8') == b'\x01\x08\x08\x08\x08'
  assert pack_addr(b'2404:6800:4005:805::1011') == \
    b'\x04$\x04h\x00@\x05\x08\x05\x00\x00\x00\x00\x00\x00\x10\x11'
  assert pack_addr(b'www.google.com') == b'\x03\x0ewww.google.com'


if __name__ == '__main__':
  test_inet_conv()
  test_parse_header()
  test_pack_header()