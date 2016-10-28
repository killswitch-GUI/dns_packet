import struct
import binascii
import numpy

class dns_struct(object):
    """
    Base class for all class objects in the project,
    this will define the needed structure types and 
    ability to decode them.
    """

    # QR, Query/Response. 1 bit.
    QR = {  0 : 'QUERY',
            1 : 'RESPONSE'
    }

    # Opcode. 4 bits.
    OPCODE = {  0 : 'QUERY',
                1 : 'IQUERY',
                2 : 'STATUS',
                4 : 'NOTIFY',
                5 : 'UPDATE'
    }

    # AA, Authoritative Answer. 1 bit.
    #  Specifies that the responding name server is an authority for the domain name in question section. 
    #  Note that the contents of the answer section may have multiple owner names because of aliases. 
    #  This bit corresponds to the name which matches the query name, or the first owner name in the answer section.
    AA = {  0 : 'NOT AUTHORITATIVE',
            1 : 'AUTHORITATIVE'
    }

    # TC, Truncated. 1 bit.
    #  Indicates that only the first 512 bytes of the reply was returned.
    TC = {  0 : 'NOT TRUNCATED',
            1 : 'TRUNCATED'
    }

    # RD, Recursion Desired. 1 bit.
    #  May be set in a query and is copied into the response. 
    #  If set, the name server is directed to pursue the query recursively. 
    #  Recursive query support is optional.
    RD = {  0 : 'NOT DESIRED',
            1 : 'DESIRED'
    }

    # RA, Recursion Available. 1 bit.
    #  Indicat es if recursive query support is available in the name server.
    RA = {  0 : 'NOT AVAILABLE',
            1 : 'AVAILABLE'
    }

    # Z. 1 bit.
    Z = {} 

    # AD, Authenticated data. 1 bit.
    AD = {} 

    # CD, Checking Disabled. 1 bit.
    CD = {}

    # Rcode, Return code. 4 bits.
    RC = {  0 : 'NO ERROR',
            1 : 'FORMAT ERROR',
            2 : 'SERVER FAILURE',
            3 : 'NAME ERROR',
            4 : 'NOT IMPLEMENTED',
            5 : 'REFUSED',
            6 : 'YXDOMAIN',
            7 : 'YXRRSET',
            8 : 'NXRRSET',
            9 : 'NOTAUTH',
            10 : 'NOTZONE',
            16 : 'BADVERS',
            17 : 'BADKEY',
            18 : 'BADTIME',
            19 : 'BADMODE',
            20 : 'BADNAME', 
            21 : 'BADALG', 
            22 : 'BADTRUNC'
    } 

    _DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")

    def byte_to_binary(self, n):
        return ''.join(str((n & (1 << i)) and 1) for i in reversed(range(8)))

    def hex_to_binary(self, h):
        return ''.join(self.byte_to_binary(ord(b)) for b in binascii.unhexlify(h))

    def _unpack_dns_upper_codes(self, byte):
        byte = self.byte_to_hex(byte)
        data = self.hex_to_binary(byte)
        qr = data[0:1]
        opcode = data[1:5]
        aa = data[5:6]
        tc = data[6:7]
        rd = data[7:8]
        return {'qr' : qr, 'opcode' : opcode, 'aa' : aa, 'tc' : tc, 'rd' : rd}

    def _unpack_dns_lower_codes(self, byte):
        byte = self.byte_to_hex(byte)
        data = self.hex_to_binary(str(byte))
        ra = data[0:1]
        z = data[1:2]
        ad = data[2:3]
        cd = data[3:4]
        rc = data[4:8]
        return {'ra' : ra, 'z' : z, 'ad' : ad, 'cd' : cd, 'rc' : rc}

    def _upack_dns_codes(self, data):
        identification = struct.unpack('!H',data[8:10])[0]       # id. 16 bits.
        lower_byte = struct.unpack('!B',data[10:11])[0]          # lower byte for 8 bits to decode
        upper_byte = struct.unpack('!B',data[11:12])[0]          # upper byte for 8 bits to decode
        total_questions = struct.unpack('!H',data[12:14])[0]     # Total Questions. 16 bits, unsigned.
        total_answers_rr = struct.unpack('!H',data[14:16])[0]    # Total Answer RRs. 16 bits, unsigned.
        total_authority_rr = struct.unpack('!H',data[16:18])[0]  # Total Authority RRs. 16 bits, unsigned.
        total_additional_rr = struct.unpack('!H',data[18:20])[0] # Total Additional RRs. 16 bits, unsigned.
        temp_dns = {'identification':identification, 
                    'total_questions':total_questions, 
                    'total_answers_rr':total_answers_rr, 
                    'total_authority_rr':total_authority_rr,
                    'total_additional_rr':total_additional_rr}
        return temp_dns

    def decode_labels(self, message, offset):
        labels = []

        while True:
            length, = struct.unpack_from("!B", message, offset)

            if (length & 0xC0) == 0xC0:
                pointer, = struct.unpack_from("!H", message, offset)
                offset += 2

                return labels + self.decode_labels(message, pointer & 0x3FFF), offset

            if (length & 0xC0) != 0x00:
                raise StandardError("unknown label encoding")

            offset += 1

            if length == 0:
                return labels, offset

            labels.append(*struct.unpack_from("!%ds" % length, message, offset))
            offset += length

    def decode_question_section(self, message, offset, qdcount):
        questions = []

        for _ in range(qdcount):
            qname, offset = self.decode_labels(message, offset)

            qtype, qclass = self._DNS_QUERY_SECTION_FORMAT.unpack_from(message, offset)
            offset += self._DNS_QUERY_SECTION_FORMAT.size

            question = {"domain_name": qname,
                        "query_type": qtype,
                        "query_class": qclass}

            questions.append(question)

        return questions, offset

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


    def unpack_udp(self, data):
        source_port = struct.unpack('!H',data[:2])[0]           # Source Port. 16 bits.
        destination_port = struct.unpack('!H',data[2:4])[0]     # Destination Port. 16 bits.
        length = struct.unpack('!H',data[4:6])[0]               # Destination Port. 16 bits.
        checksum = struct.unpack('!H',data[6:8])[0]             # Checksum. 16 bits.
        return {'src_port' : source_port, 'dst_port' : destination_port, 'length' : length, 'check_sum' : checksum}

    def unpack_dns(self, data):
        """
        Unpack dns byte data to a returned dict.
        Takes:
        data = the raw byte data from socket.

        returns:
        dns_dict = a full decoded dict of the dns packet struc.
        """
        # TODO: can you copy() from a function return data?
        lower_dict = self._unpack_dns_lower_codes(data[10:11])
        uper_dict = self._unpack_dns_upper_codes(data[11:12])
        dns_data = self._upack_dns_codes(data)
        dns_questions, question_offset = self.decode_question_section(data, 20, dns_data['total_questions'])
        print dns_questions
        print question_offset
        # build the return data
        dns_dict = lower_dict.copy()
        dns_dict.update(uper_dict)
        dns_dict.update(dns_data)
        return dns_dict
        
        
