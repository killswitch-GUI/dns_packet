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

class buffer(object):

    """
    buffer object for pointer
    """

    _START_POINTER = 0      # Poniter starter value

    _BUFFER_SIZE = 512      # Bytes

    def __init__(self, buffer_offset=self._START_POINTER, buffer_size=self._BUFFER_SIZE, verbose=False):
        """
        populates init, builds buffer object.
        example calls: struct.pack_into(fmt, buffer, offset, v1, v2, ...)
        """
        self.verbose = False
        self.offset = buffer_offset
        self.buffer = self.build_buffer(buffer_size=buffer_size)

    def build_buffer(self, buffer_size=self._BUFFER_SIZE):
        """
        build the fast buffer array.

        returns: 
        aray buffer object
        """
        buffer_size = buffer_size * 2
        return array.array('c', ' ' * buffer_size)
        
    def increment_pointer(self, increment):
        """
        increment buffer pointer object
        """
        self.offset += increment

    def decrement_pointer(self, decrement):
        """
        decrement buffer pointer object
        """
        self.offset -= decrement

    def rest_pointer(self, value=self._START_POINTER):
        """
        reset to defualt calue
        """

        self.offset = self._START_POINTER