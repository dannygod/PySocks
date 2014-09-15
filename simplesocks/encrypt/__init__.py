#!/usr/bin/env python

# Copyright (c) 2014 dannygod

import os
import sys


ROOT_PATH = os.path.realpath(os.path.join(
    os.path.split(os.path.realpath(__file__))[0], os.pardir))
try:
  import common
except ImportError:
  sys.path.append(ROOT_PATH)
  import common
