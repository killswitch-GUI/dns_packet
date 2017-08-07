# Author: Alexander Rymdeko-Harvey(@Killswitch-GUI)
# File: dns_helpers.py 
# License: BSD 3-Clause
# Copyright (c) 2016, Alexander Rymdeko-Harvey 
# All rights reserved. 
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions are met: 
#  * Redistributions of source code must retain the above copyright notice, 
#    this list of conditions and the following disclaimer. 
#  * Redistributions in binary form must reproduce the above copyright 
#    notice, this list of conditions and the following disclaimer in the 
#    documentation and/or other materials provided with the distribution. 
#  * Neither the name of  nor the names of its contributors may be used to 
#    endorse or promote products derived from this software without specific 
#    prior written permission. 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
# POSSIBILITY OF SUCH DAMAGE.
import struct
import binascii
import array

class byte_opperations(object):
    """
    class object for handling byte and 
    binary translations
    """
    def __init__(self, verbose=False):
        """
        populates init. test
        """
        pass

    def byte_to_binary(self, n):
        return ''.join(str((n & (1 << i)) and 1) for i in reversed(range(8)))

    def hex_to_binary(self, h):
        """
        :param h: Hex value to decode 
        :return: binary in string format
        """
        return ''.join(self.byte_to_binary(ord(b)) for b in binascii.unhexlify(h))

    def byte_to_hex( self, byteStr ):
        """
        Convert a byte string to it's hex string representation e.g. for output.
        http://code.activestate.com/recipes/510399-byte-to-hex-and-hex-to-byte-string-conversion/
        """
        
        # Uses list comprehension which is a fractionally faster implementation than
        # the alternative, more readable, implementation below
        #   
        #    hex = []
        #    for aChar in byteStr:
        #        hex.append( "%02X " % ord( aChar ) )
        #
        #    return ''.join( hex ).strip()        

        return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()

    def int_to_bin(self, i, fill=0):
        """
        Turns a int to a direct bin conversion as a string with out 0b
        :param i: int to parse
        :param fill: optional field to zfill with zeros
        :return: string buffer of binary data
        
        """
        bin_data = format(i, 'b')
        return bin_data

    def bin_to_byte(self, i):
        """
        converts a binary string to a hex byte char
        :param i: binary string
        :return: hex char
        """
        hex = chr(int(str(i), 2))
        return hex

class buffer(object):

    """
    buffer object for pointer
    """

    _START_POINTER = 0      # Poniter starter value

    _BUFFER_SIZE = 512      # Bytes

    def __init__(self, buffer_offset=_START_POINTER, buffer_size=_BUFFER_SIZE, verbose=False):
        """
        populates init, builds buffer object.
        example calls: struct.pack_into(fmt, buffer, offset, v1, v2, ...)
        """
        self.verbose = False
        self._offset = buffer_offset
        self._buffer = self.build_buffer(buffer_size=buffer_size)

    def build_buffer(self, buffer_size=_BUFFER_SIZE):
        """
        build the fast buffer array.

        returns: 
        aray buffer object
        """
        buffer_size = buffer_size * 2
        return array.array('c', ' ' * buffer_size)

    def pack_buffer(self, data, format_type):
        """
        pack data into the buffer

        takes:
        data = int, str etc to be packed
        format = struct format type 'i', 'H' etc..
        """
        struct.pack_into('!%s' % format_type, self._buffer, self._offset, data)
        
    def increment_pointer(self, increment):
        """
        increment buffer pointer object
        """
        self._offset += increment

    def decrement_pointer(self, decrement):
        """
        decrement buffer pointer object
        """
        self._offset -= decrement

    def rest_pointer(self, value=_START_POINTER):
        """
        reset to defualt calue
        """

        self._offset = self._START_POINTER