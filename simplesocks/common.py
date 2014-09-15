#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 dannygod

__version__ = '3.0.0'


import os
import socket
import struct
import sys
from util import value_utils
from util import logging_utils

logging = sys.modules['logging'] = logging_utils.Logging('logging')


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


def inet_ntop(family, ipstr):
  if family == socket.AF_INET:
    return socket.inet_ntoa(ipstr)
  elif family == socket.AF_INET6:
    v6addr = ':'.join(('%02X%02X' % (ord(i), ord(j)))
                      for i, j in zip(ipstr[::2], ipstr[1::2]))
    return v6addr


def inet_pton(family, addr):
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
    return ''.join((chr(i // 256) + chr(i % 256)) for i in dbyts)
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
  for family in (socket.AF_INET, socket.AF_INET6):
    try:
      r = socket.inet_pton(family, address)
      if family == socket.AF_INET6:
        return '\x04' + r
      else:
        return '\x01' + r
    except (TypeError, ValueError, OSError, IOError):
      pass
  if len(address) > 255:
    address = address[:255]  # TODO
  return '\x03' + chr(len(address)) + address


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
  return addrtype, dest_addr, dest_port, header_length
