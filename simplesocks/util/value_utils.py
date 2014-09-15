#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 dannygod

import json
import os


def WriteJson(obj, path, only_if_changed=False):
  old_dump = None
  if os.path.exists(path):
    with open(path, 'r') as oldfile:
      old_dump = oldfile.read()

  new_dump = json.dumps(obj)

  if not only_if_changed or old_dump != new_dump:
    with open(path, 'w') as outfile:
      outfile.write(new_dump)


def ReadJson(path):
  with open(path, 'r') as jsonfile:
    return json.load(jsonfile)


def ReadPyValues(path):
  with open(path, 'r') as f:
    return eval(f.read(), {'__builtins__': None}, None)


