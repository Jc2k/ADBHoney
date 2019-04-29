"""
@author: Geir Sporsheim
@see: git repo https://android.googlesource.com/platform/system/core/
@see: source file adb/adb.h
"""

import struct
import logging

log = logging.getLogger()

VERSION = 0x01000000  # ADB protocol version
MAX_PAYLOAD = 4096

# Message command constants
CMD_SYNC = 0x434e5953
CMD_CNXN = 0x4e584e43
CMD_OPEN = 0x4e45504f
CMD_OKAY = 0x59414b4f
CMD_CLSE = 0x45534c43
CMD_WRTE = 0x45545257


def getCommandString(commandCode):
    """Returns a readable string representation of a message code
    """
    return struct.pack('<L', commandCode)


class AdbMessage(object):
    def __init__(self, command, arg0, arg1, data=b''):
        self.command = command
        self.arg0 = arg0
        self.arg1 = arg1
        self.data = data

    @property
    def checksum(self):
        # The checksum is just a sum of all the bytes. I swear.
        data = self.data
        if isinstance(data, bytearray):
            total = sum(data)
        elif isinstance(data, bytes):
            if data and isinstance(data[0], bytes):
                # Python 2 bytes (str) index as single-character strings.
                total = sum(map(ord, data))
            else:
                # Python 3 bytes index as numbers (and PY2 empty strings sum() to 0)
                total = sum(data)
        else:
            # Unicode strings (should never see?)
            total = sum(map(ord, data))
        print(total)
        return total & 0xFFFFFFFF

    @property
    def header(self):
        data_check = sum(self.data) & 0xFFFFFFFF

        #data_check = '\xbc\xb1\xa7\xb1'
        #data_check = ''
        #import zlib
        #data_check = zlib.crc32(self.data)
        magic = self.command ^ 0xffffffff
        header = AdbMessageHeader(self.command,
                                self.arg0,
                                self.arg1,
                                len(self.data),
                                self.checksum,
                                magic)
        return header

    @classmethod
    def decode(cls, data):
        header, data = AdbMessageHeader.decode(data)
        # if len(data) < header.data_length:
        #    return
        message = cls(header.command, header.arg0, header.arg1, data)
        message.validate(header)
        return message, data[header.data_length:]

    def encode(self):
        return self.header.encode() + self.data

    def validate(self, header):
        #assert self.header == header
        assert True

    def __eq__(self, other):
        return self.header == other.header and self.data == other.data

    def __repr__(self):
        #if len(self.data) > 32:
        #    data = "*"
        #else:
        #    data = self.data
        return "%s(%r)" % (self.header, self.data)


class AdbMessageHeader(tuple):
    _fmt = '<6L'

    def __new__(cls, command, arg0, arg1, data_length, data_check, magic):
        """
        @param command: command identifier constant
        @param arg0: first argument
        @param arg1: second argument
        @param length: length of payload (0 is allowed)
        @param data_check: checksum of data payload
        @param magic: command ^ 0xffffffff
        """
        return tuple.__new__(cls, (command,
                                   arg0,
                                   arg1,
                                   data_length,
                                   data_check,
                                   magic))

    command = property(lambda self: self[0])
    arg0 = property(lambda self: self[1])
    arg1 = property(lambda self: self[2])
    data_length = property(lambda self: self[3])
    data_check = property(lambda self: self[4])
    magic = property(lambda self: self[5])

    def encode(self):
        return struct.pack(self._fmt,
                           self.command,
                           self.arg0,
                           self.arg1,
                           self.data_length,
                           self.data_check,
                           self.magic)

    @classmethod
    def decode(cls, data):
        length = struct.calcsize(cls._fmt)
        # if len(data) < length:
        #    return
        args = struct.unpack(cls._fmt, data[:length])
        return cls(*args), data[length:]

    def __str__(self, *args, **kwargs):
        return str((getCommandString(self.command),
                    self.arg0, self.arg1, self.data_length,
                    self.data_check, self.magic))
