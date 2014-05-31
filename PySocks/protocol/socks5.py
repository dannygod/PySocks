#!/usr/bin/env python
# coding:utf-8

# Copyright (c) 2014 dannygod

import socket
import struct

# handle socks5 protocol, see http://www.ietf.org/rfc/rfc1928.txt

# The client connects to the server, and sends a version
# identifier/method selection message:
#
#     +----+----------+----------+
#     |VER | NMETHODS | METHODS  |
#     +----+----------+----------+
#     | 1  |    1     | 1 to 255 |
#     +----+----------+----------+
#
# The VER field is set to X'05' for this version of the protocol.  The
# NMETHODS field contains the number of method identifier octets that
# appear in the METHODS field.
#
# The server selects from one of the methods given in METHODS, and
#    sends a METHOD selection message:
#
#     +----+--------+
#     |VER | METHOD |
#     +----+--------+
#     | 1  |   1    |
#     +----+--------+
#
#  The values currently defined for METHOD are:
#         o  X'00' NO AUTHENTICATION REQUIRED
#         o  X'01' GSSAPI
#         o  X'02' USERNAME/PASSWORD
#         o  X'03' to X'7F' IANA ASSIGNED
#         o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
#         o  X'FF' NO ACCEPTABLE METHODS

# method not list here is not supported now
SOCKS5_METHOD_NO_AUTH = 0x00
SOCKS5_METHOD_USERNAME_PASSWORD = 0x02
SOCKS5_METHOD_NO_ACCEPT = 0xff


def getClientRequestMethod(data):
  if not data or len(data) < 3:
    return SOCKS5_METHOD_NO_ACCEPT

  return ord(data[2])


def responseMethodToClient(method):
  if method == SOCKS5_METHOD_NO_AUTH:
    return "\x05\x00"
  elif method == SOCKS5_METHOD_USERNAME_PASSWORD:
    return "\x05\x02"
  else:
    return "\x05\xff"


# The SOCKS request is formed as follows:
#
#   +----+-----+-------+------+----------+----------+
#   |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
#   +----+-----+-------+------+----------+----------+
#   | 1  |  1  | X'00' |  1   | Variable |    2     |
#   +----+-----+-------+------+----------+----------+
# Where:
#      o  VER    protocol version: X'05'
#      o  CMD
#         o  CONNECT X'01'
#         o  BIND X'02'
#         o  UDP ASSOCIATE X'03'
#      o  RSV    RESERVED
#      o  ATYP   address type of following address
#         o  IP V4 address: X'01'
#         o  DOMAINNAME: X'03'
#         o  IP V6 address: X'04'
#      o  DST.ADDR       desired destination address
#      o  DST.PORT desired destination port in network octet
#         order
SOCKS5_CMD_CONNECT = 0x01

# return value:
#   (cmd, addrtype, addr_to_send, addr, port)
def parseClientRequest(rfile):
  data = rfile.read(4) or '\x00' * 4

  cmd = ord(data[1])
  if cmd == SOCKS5_CMD_CONNECT:
    pass
  else:
    return (None, None, None, None, None)

  addrtype = ord(data[3])
  addr_to_send = data[3]

  if addrtype == 1:
    addr_ip = rfile.read(4)
    addr = socket.inet_ntoa(addr_ip)
    addr_to_send += addr_ip
  elif addrtype == 3:
    addr_len = rfile.read(1)
    addr = rfile.read(ord(addr_len))
    addr_to_send += addr_len + addr
  elif addrtype == 4:
    addr_ip = rfile.read(16)
    addr = socket.inet_ntop(socket.AF_INET6, addr_ip)
    addr_to_send += addr_ip
  else:
    return (cmd, None, None, None, None)

  addr_port = rfile.read(2)
  addr_to_send += addr_port

  port = struct.unpack(">H", addr_port)

  return (cmd, addrtype, addr_to_send, addr, port[0])


# The SOCKS request information is sent by the client as soon as it has
# established a connection to the SOCKS server, and completed the
# authentication negotiations.  The server evaluates the request, and
# returns a reply formed as follows:
#
#     +----+-----+-------+------+----------+----------+
#     |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
#     +----+-----+-------+------+----------+----------+
#     | 1  |  1  | X'00' |  1   | Variable |    2     |
#     +----+-----+-------+------+----------+----------+
#
# Where:
#      o  VER    protocol version: X'05'
#      o  REP    Reply field:
#         o  X'00' succeeded
#         o  X'01' general SOCKS server failure
#         o  X'02' connection not allowed by ruleset
#         o  X'03' Network unreachable
#         o  X'04' Host unreachable
#         o  X'05' Connection refused
#         o  X'06' TTL expired
#         o  X'07' Command not supported
#         o  X'08' Address type not supported
#         o  X'09' to X'FF' unassigned
#      o  RSV    RESERVED
#      o  ATYP   address type of following address
#         o  IP V4 address: X'01'
#         o  DOMAINNAME: X'03'
#         o  IP V6 address: X'04'
#      o  BND.ADDR       server bound address
#      o  BND.PORT       server bound port in network octet order
def replyClientRequest():
  bind_addr = socket.inet_aton('0.0.0.0')
  bind_port = struct.pack(">H", 2222)
  return "\x05\x00\x00\x01" + bind_addr + bind_port
