#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 dannygod


import os
import sys
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


