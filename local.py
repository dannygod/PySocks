#!/usr/bin/env python
# coding:utf-8

__version__ = '1.0.0'

import socket
import select
import SocketServer
import struct
import string
import hashlib
import sys
import os
import logging
import time
import traceback
try:
    import ctypes
except ImportError:
    ctypes = None
try:
    import OpenSSL
except ImportError:
    OpenSSL = None

class Logging(type(sys)):
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
logging = sys.modules['logging'] = Logging('logging')

class Common(object):
    """Global Config Object"""

    def __init__(self):
        """load config from config"""
        __fd = open('config', 'rb')
        __raw_data = __fd.read()
        __fd.close()

        self.CONFIG = eval(__raw_data, {'__builtins__': None}, None)

        #listen
        self.LISTEN_IP            = self.CONFIG['ip']
        self.LISTEN_PORT          = self.CONFIG['local_port']
        self.LISTEN_VISIBLE       = self.CONFIG['visible']
        self.LISTEN_DEBUGINFO     = self.CONFIG['debuginfo'] if self.CONFIG.has_key('debuginfo') else 0

        #server info
        self.SOCKS5_SERVER           = self.CONFIG['server']
        self.SOCKS5_SERVER_PORT      = self.CONFIG['server_port']
        self.SOCKS5_PASSWORD         = self.CONFIG['password']

    def info(self):
        info = ''
        info += '------------------------------------------------------\n'
        info += 'ShadowSocks Version    : %s (python/%s pyopenssl/%s)\n' % (__version__, sys.version.partition(' ')[0], (OpenSSL.version.__version__ if OpenSSL else 'Disabled'))
        info += 'Listen Address         : %s:%d\n' % (self.LISTEN_IP, self.LISTEN_PORT)
        info += 'Debug INFO             : %s\n' % self.LISTEN_DEBUGINFO if self.LISTEN_DEBUGINFO else ''
        info += 'SOCKS5 Server          : %s:%d\n' % (self.SOCKS5_SERVER, self.SOCKS5_SERVER_PORT)
        info += '------------------------------------------------------\n'
        return info

common = Common()

def get_table(key):
    m = hashlib.md5()
    m.update(key)
    s = m.digest()
    (a, b) = struct.unpack('<QQ', s)
    table = [c for c in string.maketrans('', '')]
    for i in xrange(1, 1024):
        table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
    return table


class ThreadingTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class Socks5Server(SocketServer.StreamRequestHandler):
    def handle_tcp(self, sock, remote):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    if remote.send(self.encrypt(sock.recv(4096))) <= 0:
                        break
                if remote in r:
                    if sock.send(self.decrypt(remote.recv(4096))) <= 0:
                        break
        finally:
            sock.close()
            remote.close()

    def encrypt(self, data):
        return data.translate(encrypt_table)

    def decrypt(self, data):
        return data.translate(decrypt_table)

    def send_encrypt(self, sock, data):
        sock.send(self.encrypt(data))

    def handle(self):
        try:
            sock = self.connection
            sock.recv(262)
            sock.send("\x05\x00")
            data = self.rfile.read(4)
            mode = ord(data[1])
            if mode != 1:
                logging.warn('mode != 1')
                return
            addrtype = ord(data[3])
            addr_to_send = data[3]
            if addrtype == 1:
                addr_ip = self.rfile.read(4)
                addr = socket.inet_ntoa(addr_ip)
                addr_to_send += addr_ip
            elif addrtype == 3:
                addr_len = sock.recv(1)
                addr = self.rfile.read(ord(addr_len))
                addr_to_send += addr_len + addr
            else:
                logging.warn('addr_type not support')
                # not support
                return
            addr_port = self.rfile.read(2)
            addr_to_send += addr_port
            port = struct.unpack('>H', addr_port)
            try:
                reply = "\x05\x00\x00\x01"
                reply += socket.inet_aton('0.0.0.0') + struct.pack(">H", 2222)
                sock.send(reply)
                # reply immediately
                if '-6' in sys.argv[1:]:
                    remote = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                else:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                remote.connect((common.SOCKS5_SERVER, common.SOCKS5_SERVER_PORT))
                self.send_encrypt(remote, addr_to_send)
                logging.info('connecting %s:%d' % (addr, port[0]))
            except socket.error as e:
                logging.error('socket.error %s in send' % e)
                return
            self.handle_tcp(sock, remote)
        except socket.error as e:
            logging.error('socket.error %s (Do you set up a wrong password?)' % e)

def pre_start():
    if sys.platform == 'cygwin':
        logging.critical('cygwin platform is not supported, please download `http://www.python.org/getit/`')
        sys.exit(-1)
    if ctypes and os.name == 'nt':
        ctypes.windll.kernel32.SetConsoleTitleW(u'ShadowSocks v%s' % __version__)
        if not common.LISTEN_VISIBLE:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 0)
        else:
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 1)

        blacklist = {
                        '360safe' : False, # http://s.weibo.com/weibo/goagent%2520360%2520%25E5%258D%25B8%25E8%25BD%25BD
                        'QQProtect' : False, # http://s.weibo.com/weibo/goagent%2520qqprotect
                    }
        softwares = [k for k,v in blacklist.items() if v]
        if softwares:
            tasklist = os.popen('tasklist').read().lower()
            softwares = [x for x in softwares if x.lower()in tasklist]
            if softwares:
                error = u'某些安全软件(如 %s)可能和本软件存在冲突，造成 CPU 占用过高。\n如有此现象建议暂时退出此安全软件来继续运行GoAgent' % ','.join(softwares)
                ctypes.windll.user32.MessageBoxW(None, error, u'ShadowSocks 建议', 0)
                #sys.exit(0)

def main():
    global __file__
    __file__ = os.path.abspath(__file__)
    if os.path.islink(__file__):
        __file__ = getattr(os, 'readlink', lambda x:x)(__file__)
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    logging.basicConfig(level=logging.DEBUG if common.LISTEN_DEBUGINFO else logging.INFO, format='%(levelname)s - %(asctime)s %(message)s', datefmt='[%b %d %H:%M:%S]')

    pre_start()
    sys.stdout.write(common.info())


    try:
        server = ThreadingTCPServer(('', common.LISTEN_PORT), Socks5Server)
        server.allow_reuse_address = True
        logging.info("starting server at port %d ..." % common.LISTEN_PORT)
        server.serve_forever()
    except socket.error, e:
        logging.error(e)
#    server = gevent.server.StreamServer((common.LISTEN_IP, common.LISTEN_PORT), socks5proxy_handler)
#    server.serve_forever()

if __name__ == '__main__':
    try:
        encrypt_table = ''.join(get_table(common.SOCKS5_PASSWORD))
        decrypt_table = string.maketrans(encrypt_table, string.maketrans('', ''))

        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        if ctypes and os.name == 'nt':
            ctypes.windll.user32.ShowWindow(ctypes.windll.kernel32.GetConsoleWindow(), 1)
        raise
