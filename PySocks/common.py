#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 dannygod

__version__ = '2.2.0'


import os
import sys
from util import value_utils


class Common(object):
  """Global Config Object"""

  def __init__(self):
    """load config from config"""
    config_path = os.path.join(os.path.dirname(__file__), os.pardir, 'config')
    self.CONFIG = value_utils.ReadPyValues(config_path)

    # listen
    self.LISTEN_IP            = self.CONFIG['ip']
    self.LISTEN_PORT          = self.CONFIG['local_port']
    self.LISTEN_VISIBLE       = self.CONFIG['visible']
    self.LISTEN_DEBUGINFO     = self.CONFIG['debuginfo'] if self.CONFIG.has_key('debuginfo') else 0

    # server info
    self.SOCKS5_SERVER           = self.CONFIG['server']
    self.SOCKS5_SERVER_PORT      = self.CONFIG['server_port']
    self.SOCKS5_PASSWORD         = self.CONFIG['password']
    self.SOCKS5_ENCRYPT_METHOD   = self.CONFIG['method']

    self.TIMEOUT = self.CONFIG['timeout']

    # app version
    self.VERSION = __version__

  def info(self):
    info = ''
    info += '------------------------------------------------------\n'
    info += 'ShadowSocks Version    : %s (python/%s)\n' % (self.VERSION, sys.version.partition(' ')[0])
    info += 'Listen Address         : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
    info += 'Debug INFO             : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
    info += 'SOCKS5 Server          : %s:%d\n' % (self.SOCKS5_SERVER, self.SOCKS5_SERVER_PORT)
    info += 'TimeOut                : %d\n' % self.TIMEOUT
    info += '------------------------------------------------------\n'
    return info
