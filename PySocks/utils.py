#!/usr/bin/python
# -*- coding: utf-8 -*-

__version__ = '2.1.0'

import os
import sys
import logging
import time
try:
  import ctypes
except ImportError:
  ctypes = None


class Logging(type(sys)):
  NOLOGGING = 100
  CRITICAL = 50
  FATAL = CRITICAL
  ERROR = 40
  WARNING = 30
  WARN = WARNING
  INFO = 20
  DEBUG = 10
  NOTSET = 0

  def __init__(self, *args, **kwargs):
    self.level = self.__class__.INFO
    if self.level > self.__class__.DEBUG:
      self.debug = self.dummy
    self.__write = __write = sys.stderr.write
    self.isatty = getattr(sys.stderr, 'isatty', lambda:False)()
    self.__set_error_color = lambda:None
    self.__set_warning_color = lambda:None
    self.__reset_color = lambda:None
    if self.isatty:
      if os.name == 'nt':
        SetConsoleTextAttribute = ctypes.windll.kernel32.SetConsoleTextAttribute
        GetStdHandle = ctypes.windll.kernel32.GetStdHandle
        self.__set_error_color = lambda:SetConsoleTextAttribute(GetStdHandle(-11), 0x04)
        self.__set_warning_color = lambda:SetConsoleTextAttribute(GetStdHandle(-11), 0x06)
        self.__reset_color = lambda:SetConsoleTextAttribute(GetStdHandle(-11), 0x07)
      elif os.name == 'posix':
        self.__set_error_color = lambda:__write('\033[31m')
        self.__set_warning_color = lambda:__write('\033[33m')
        self.__reset_color = lambda:__write('\033[0m')

  @classmethod
  def getLogger(cls, *args, **kwargs):
    return cls(*args, **kwargs)

  def basicConfig(self, *args, **kwargs):
    self.level = kwargs.get('level', self.__class__.INFO)
    if self.level > self.__class__.DEBUG:
        self.debug = self.dummy
    if self.level == self.__class__.NOLOGGING:
      self.debug = self.dummy
      self.info = self.dummy
      self.warning = self.dummy
      self.error = self.dummy
      self.critical = self.dummy

  def log(self, level, fmt, *args, **kwargs):
    self.__write('%s - - [%s] %s\n' % (level, time.ctime()[4:-5], fmt%args))

  def dummy(self, *args, **kwargs):
    pass

  def debug(self, fmt, *args, **kwargs):
    self.log('DEBUG', fmt, *args, **kwargs)

  def info(self, fmt, *args, **kwargs):
    self.log('INFO', fmt, *args)

  def warning(self, fmt, *args, **kwargs):
    self.__set_warning_color()
    self.log('WARNING', fmt, *args, **kwargs)
    self.__reset_color()

  def warn(self, fmt, *args, **kwargs):
    self.warning(fmt, *args, **kwargs)

  def error(self, fmt, *args, **kwargs):
    self.__set_error_color()
    self.log('ERROR', fmt, *args, **kwargs)
    self.__reset_color()

  def exception(self, fmt, *args, **kwargs):
    self.error(fmt, *args, **kwargs)
    traceback.print_exc(file=sys.stderr)

  def critical(self, fmt, *args, **kwargs):
    self.__set_error_color()
    self.log('CRITICAL', fmt, *args, **kwargs)
    self.__reset_color()


class Common(object):
  """Global Config Object"""
  
  def __init__(self):
    """load config from config"""
    with open('config') as f:
        __raw_data = f.read()
    
    self.CONFIG = eval(__raw_data, {'__builtins__': None}, None)
    
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
