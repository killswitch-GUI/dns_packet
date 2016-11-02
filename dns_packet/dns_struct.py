# Author: Alexander Rymdeko-Harvey(@Killswitch-GUI)
# File: dns_struct.py 
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
import socket
import dns_helpers

class dns_encode_struct(dns_helpers.byte_opperations):
    """
    base class for all encode objects with
    proper ability to build DNS packet structure
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

    # rr types
    RR_TYPE = { 1 : 'A',
                2 : 'NS',
                3 : 'MD', 
                4 : 'MF',
                5 : 'CNAME',
                6 : 'SOA',
                7 : 'MB',
                8 : 'MG',
                9 : 'MR',
                10 : 'NULL',
                11 : 'WKS',
                12 : 'PTR',
                13 : 'HINFO',
                14 : 'MINFO',
                15 : 'MX',
                16 : 'TXT',
                17 : 'RP',
                18 : 'AFSDB',
                19 : 'X25',
                20 : 'ISDN',
                21 : 'RT',
                22 : 'NSAP',
                23 : 'NSAP-PTR',
                24 : 'SIG',
                25 : 'KEY',
                26 : 'KEY',
                27 : 'GPOS',
                28 : 'AAAA',
                29 : 'LOC',
                30 : 'NXT',
                31 : 'EID',
                32 : 'NETBIOS',
                33 : 'SRV',
                34 : 'ATMA',
                35 : 'NAPTR',
                36 : 'KX',
                37 : 'CERT',
                38 : 'A6',
                39 : 'DNAME',
                40 : 'SINK',
                41 : 'OPT',
                42 : 'APL',
                43 : 'DS',
                44 : 'SSHFP',
                45 : 'IPSECKEY',
                46 : 'RRSIG',
                47 : 'NSEC',
                48 : 'DNSKEY',
                49 : 'DHCID',
                50 : 'NSEC3',
                51 : 'NSEC3PARAM',
                52 : 'TLSA',
                55 : 'HIP',
                56 : 'NINFO',
                57 : 'RKEY',
                58 : 'TALINK',
                59 : 'CHILD DS',
                99 : 'SPF',
                100 : 'UINFO',
                101 : 'UID',
                102 : 'GID',
                103 : 'UNSPEC',
                249 : 'TKEY',
                250 : 'TSIG',
                251 : 'IXFR',
                252 : 'AXFR',
                253 : 'MAILB',
                254 : 'MAILA',
                255 : '*',
                256 : 'URI',
                257 : 'CAA',
                32768 : 'DNSSECT',
                32768 : 'DNSSECL'
    }

    RR_CLASS={  1 : 'IN',
                3 : 'CH',
                4 : 'HS',
                254 : 'NONE',
                255 : 'ANY'                
    }


    def __init__(self, verbose=False):
        """
        populates init.
        """
        slef.verbose = False



class dns_decode_struct(dns_helpers.byte_opperations):
    """
    Base class for all class objects in the project,
    this will define the needed structure types and 
    ability to decode them.
    https://tools.ietf.org/html/rfc1035#section-4.1.4
    http://www.zytrax.com/books/dns/ch15/#rdata
    http://www.networksorcery.com/enp/protocol/dns.htm#Answer%20RRs
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

    # rr types
    RR_TYPE = { 1 : 'A',
                2 : 'NS',
                3 : 'MD', 
                4 : 'MF',
                5 : 'CNAME',
                6 : 'SOA',
                7 : 'MB',
                8 : 'MG',
                9 : 'MR',
                10 : 'NULL',
                11 : 'WKS',
                12 : 'PTR',
                13 : 'HINFO',
                14 : 'MINFO',
                15 : 'MX',
                16 : 'TXT',
                17 : 'RP',
                18 : 'AFSDB',
                19 : 'X25',
                20 : 'ISDN',
                21 : 'RT',
                22 : 'NSAP',
                23 : 'NSAP-PTR',
                24 : 'SIG',
                25 : 'KEY',
                26 : 'KEY',
                27 : 'GPOS',
                28 : 'AAAA',
                29 : 'LOC',
                30 : 'NXT',
                31 : 'EID',
                32 : 'NETBIOS',
                33 : 'SRV',
                34 : 'ATMA',
                35 : 'NAPTR',
                36 : 'KX',
                37 : 'CERT',
                38 : 'A6',
                39 : 'DNAME',
                40 : 'SINK',
                41 : 'OPT',
                42 : 'APL',
                43 : 'DS',
                44 : 'SSHFP',
                45 : 'IPSECKEY',
                46 : 'RRSIG',
                47 : 'NSEC',
                48 : 'DNSKEY',
                49 : 'DHCID',
                50 : 'NSEC3',
                51 : 'NSEC3PARAM',
                52 : 'TLSA',
                55 : 'HIP',
                56 : 'NINFO',
                57 : 'RKEY',
                58 : 'TALINK',
                59 : 'CHILD DS',
                99 : 'SPF',
                100 : 'UINFO',
                101 : 'UID',
                102 : 'GID',
                103 : 'UNSPEC',
                249 : 'TKEY',
                250 : 'TSIG',
                251 : 'IXFR',
                252 : 'AXFR',
                253 : 'MAILB',
                254 : 'MAILA',
                255 : '*',
                256 : 'URI',
                257 : 'CAA',
                32768 : 'DNSSECT',
                32768 : 'DNSSECL'
    }

    RR_CLASS={  1 : 'IN',
                3 : 'CH',
                4 : 'HS',
                254 : 'NONE',
                255 : 'ANY'                
    }


    _DNS_QUERY_SECTION_FORMAT = struct.Struct("!2H")

    def __init__(self, verbose=False):
        """
        populates init.
        """
        dns_helpers.byte_opperations.__init__(self)


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

    def _unpack_dns_rr(self, data, offset, arcount):
        """
        Unpakcs the dns resource record that is variable length.
        Using either the label method or pointer method.

        Takes:
        data = byte data from dns packet
        offset = int offset from query struc
        arcount = int specifying the number of resource records
        """
        # --------------------------------------------------------
        # |        | This name reflects the QNAME of the question  
        # |  Name  | i.e. any may take one of TWO formats.
        # |        | (label format defined for QNAME or pointer )
        # --------------------------------------------------------
        # |        | Unsigned 16 bit value. The resource record  
        # |  Type  | types - determines the content of the RDATA
        # |        | field.
        # --------------------------------------------------------
        # |        | Unsigned 16 bit value. The CLASS of resource 
        # | Class  | records being requested, for example, 
        # |        | Internet, CHAOS etc.
        # --------------------------------------------------------
        # |        | Unsigned 32 bit value. The time in seconds 
        # |   TTL  | that the record may be cached. A value of 0 
        # |        | indicates the record should not be cached.
        # --------------------------------------------------------
        # |        | Unsigned 16-bit value that defines the length 
        # |RDLENGTH| in bytes (octets) of the RDATA record.
        # |        |
        # --------------------------------------------------------
        # |        | Each (or rather most) resource record types 
        # |  RDATA | have a specific RDATA format which reflect 
        # |        | their resource record format.
        # --------------------------------------------------------
        answers = []
        offset_pointer = offset
        for _ in range(arcount):
            # set if we are using 
            name_pointer = self._check_dns_rr_pointer(data[offset_pointer:offset_pointer+1])
            if name_pointer:
                # use pointer system
                labels, offset_pointer = self._decode_rr_pointer(data, offset_pointer)
                #print self.decode_labels(data,offset_pointer)
            else:
                # using label system
                labels, offset_pointer = self._decode_rr_name_label(data,offset_pointer)
            rr_type, offset_pointer = self._decode_rr_type(data,offset_pointer)
            rr_class, offset_pointer = self._decode_rr_class(data,offset_pointer)
            rr_ttl, offset_pointer = self._decode_rr_ttl(data,offset_pointer)
            rr_length, offset_pointer = self._decode_rr_length(data,offset_pointer)
            rr_rdata, offset_pointer = self._decode_rdata(data, offset_pointer, rr_length, rr_type)
            answers.append({'label':labels,'type':rr_type,'class':rr_class,'ttl':rr_ttl,'rdata':rr_rdata})
        return answers, offset_pointer

    def _unpack_dns_additional_rr(self, data,offset, arcount):
        """
        decode additional records have exactly the same format as Answer records it is simply their 
        position in an additional section that determines they are additional records.
        """
        additional_answer = []
        offset_pointer = offset
        for _ in range(arcount):
            #name_pointer = self._check_dns_rr_pointer(data[offset_pointer:offset_pointer+1])
            #if name_pointer:
                # use pointer system
            #    labels, offset_pointer = self._decode_rr_pointer(data, offset_pointer)
                #print self.decode_labels(data,offset_pointer)
            #else:
            #    # using label system
            labels, offset_pointer = self.decode_labels(data,offset_pointer)
            rr_type, offset_pointer = self._decode_rr_type(data,offset_pointer)
            rr_class, offset_pointer = self._decode_rr_class(data,offset_pointer)
            rr_ttl, offset_pointer = self._decode_rr_ttl(data,offset_pointer)
            rr_length, offset_pointer = self._decode_rr_length(data,offset_pointer)
            rr_rdata, offset_pointer = self._decode_rdata(data, offset_pointer, rr_length, rr_type)
            additional_answer.append({'label':labels,'type':rr_type,'class':rr_class,'ttl':rr_ttl,'rdata':rr_rdata})
        return additional_answer, offset_pointer

    def _decode_rdata(self, data, offset, rr_length, rr_type):
        """
        decode resource record types have a specific RDATA 
        format which reflect their resource record.
        returns a custom dict object for eacy TYPE
        """
        rdata = {}
        if self.RR_TYPE[rr_type] == self.RR_TYPE[1]:
            # A record
            rdata = self._decode_rdata_a(data, offset, rr_length)
        if self.RR_TYPE[rr_type] == self.RR_TYPE[28]:
            # AAAA record
            rdata = self._decode_rdata_aaaa(data, offset, rr_length)
        if self.RR_TYPE[rr_type] == self.RR_TYPE[16]:
            # TXT record
            rdata = self._decode_rdata_txt(data, offset, rr_length)
        if self.RR_TYPE[rr_type] == self.RR_TYPE[15]:
            # MX record
            rdata = self._decode_rdata_mx(data, offset, rr_length)
        if self.RR_TYPE[rr_type] == self.RR_TYPE[6]:
            # SOA record
            rdata = self._decode_rdata_soa(data, offset, rr_length)
        if self.RR_TYPE[rr_type] == self.RR_TYPE[2]:
            # NS record 
            rdata = self._decode_rdata_ns(data, offset, rr_length)
        offset += rr_length
        return rdata, offset

    def _decode_rdata_soa(self, data, offset, rr_length):
        """
        decode a soa record
        """
        # Primary NS  Variable length. The name of the Primary Master for the domain. 
        #   May be a label, pointer or any combination.
        # Admin MB    Variable length. The administrator's mailbox. 
        #   May be a label, pointer or any combination.
        # Serial Number   Unsigned 32-bit integer.
        # Refresh interval    Unsigned 32-bit integer.
        # Retry Interval  Unsigned 32-bit integer.
        # Expiration Limit    Unsigned 32-bit integer.
        # Minimum TTL Unsigned 32-bit integer.
        primary_ns, offset = self.decode_labels(data, offset)
        admin_mb, offset = self.decode_labels(data, offset)
        serial = struct.unpack('!L',data[offset:offset+4])[0] 
        offset += 4
        refresh = struct.unpack('!L',data[offset:offset+4])[0] 
        offset += 4
        retry = struct.unpack('!L',data[offset:offset+4])[0] 
        offset += 4
        expiration = struct.unpack('!L',data[offset:offset+4])[0] 
        offset += 4
        min_ttl = struct.unpack('!L',data[offset:offset+4])[0] 
        return {'ns':primary_ns,'mb':admin_mb,'serial':serial,'refresh':refresh,'retry':retry,'expiration':expiration,'ttl':min_ttl}

    def _decode_rdata_txt(self, data, offset, rr_length):
        """
        decode rdata TXT record.
        """
        txt = struct.unpack('!%ds' % rr_length,data[offset:offset+rr_length])[0]
        return txt

    def _decode_rdata_aaaa(self, data, offset, rr_length):
        """
        decode rdata AAAA record.
        """
        # TODO: add in AAAA support 
        # IP Address    16 octets representing the IP address
        #ipv6 = struct.unpack('!QQ', data[offset:offset+rr_length])[0]
        return socket.inet_ntop(socket.AF_INET6, str(data[offset:offset+rr_length]))

    def _decode_rdata_a(self, data, offset, rr_length):
        """
        decode rdata A record.
        """
        # IP Address   Unsigned 32-bit value representing the IP address
        return socket.inet_ntoa(data[offset:offset+rr_length])

    def _decode_rdata_ns(self, data, offset, rr_length):
        """
        decode rdata NS record
        """
        # Name May be a label, pointer or any combination.
        return self.decode_labels(data, offset)

    def _decode_rdata_mx(self, data, offset, rr_length):
        """
        decode rdata MX record.
        """
        # Preference      Unsigned 16-bit integer.
        # Mail Exchanger  The name host name that provides the service. May be a label, pointer or any combination.

        pref = struct.unpack('!H',data[offset:offset+2])[0]
        offset += 2
        if self._check_dns_rr_pointer(data[offset:offset+1]):
            # name pointer used
            offset += 1
            mail_exch, offset = self._decode_rr_pointer(data, offset)
        else:
            mail_exch, offset = self.decode_labels(data,offset)
        return {'prefrence':pref, 'mx':mail_exch}

    def _decode_rr_length(self, data, offset):
        """
        decode the RDLENGTH Unsigned 16-bit value that 
        defines the length in bytes (octets).
        """
        rr_length = struct.unpack('!H',data[offset:offset+2])[0]
        offset += 2
        return rr_length, offset

    def _decode_rr_ttl(self, data, offset):
        """
        decode the TTL unsigned 32 bit value.
        """
        rr_ttl = struct.unpack('!I',data[offset:offset+4])[0]
        offset += 4
        return rr_ttl, offset

    def _decode_rr_class(self, data, offset):
        """
        decode the Class. 16 bits, unsigned.
        """
        rr_class = struct.unpack('!H',data[offset:offset+2])[0]     # Class. 16 bits, unsigned.
        offset += 2
        return rr_class, offset 

    def _decode_rr_type(self, data, offset):
        """
        decode the type 16 bit int.
        """
        rr_type = struct.unpack('!H',data[offset:offset+2])[0]     # Type. 16 bits, unsigned.
        offset += 2
        return rr_type, offset


    def _decode_rr_name_label(self, message, offset):
        """
        decode a label format rr 
        """
        #print 'total bytes: ' + str(len(message))

        labels = []
        while True:
            length, = struct.unpack_from("!B", message, offset)
            offset += 1
            if length == 0:
                return labels, offset
            labels.append(*struct.unpack_from("!%ds" % length, message, offset))
            offset += length

    def _decode_rr_pointer(self, data, offset):
        """
        decode the pointer loction and parse
        the lable associated.
        takes:
        data = byte data
        offset = offset to start of pointer tag
        """ 
        # https://tools.ietf.org/html/rfc1035#section-4.1.4
        # DNS Name type decode using bit type:
        # --------------------------------------------------------------------
        # | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 |15
        # -------------------------
        # | 1 | 1 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0  | 0  | 1  | 1  | 0  |0
        # --------------------------------------------------------------------
        # == 0x0c = 12 byte offset
        # 16 bit int that 2-15 bit locations are the offset from start 
        # of the dns packet
        p, = struct.unpack_from("!H", data, offset)
        value = p & 0x3FFF
        value = value - 2
        value = value * 2
        offset += 2
        label, return_offset = self._decode_rr_name_label(data,value)
        return label, offset

    def _check_dns_rr_pointer(self, byte):
        """
        check if byte is a pointer or lable type.
        takes:
        byte = a single byte of data to check 

        returns:
        bool = true or false
        """
        # DNS Name type decode using bit type:
        # -------------------------
        # | 0 | 1 | 2 | 3 | 4 etc..
        # -------------------------
        # | 1 | 1 | 0 | 0 | 0 etc..
        # -------------------------
        # if first two bits are set we are using a pointer type
        # for data compression 

        byte = self.byte_to_hex(byte)
        data = self.hex_to_binary(str(byte))
        if data[0:1] == '1' and data[1:2] == '1':
            return True
        else:
            return False


    def decode_labels(self, message, offset):
        labels = []
        while True:
            length, = struct.unpack_from("!B", message, offset)

            if (length & 0xC0) == 0xC0:
                pointer, = struct.unpack_from("!H", message, offset)
                offset += 2
                pointer = pointer & 0x3FFF
                pointer += 8
                l, off = self.decode_labels(message, pointer)
                labels += l
                return labels, offset

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
        # TODO: can you copy() from a function return s?s
        lower_dict = self._unpack_dns_lower_codes(data[10:11])
        dns_dict = lower_dict.copy()
        uper_dict = self._unpack_dns_upper_codes(data[11:12])
        dns_dict.update(uper_dict)
        dns_data = self._upack_dns_codes(data)
        dns_dict.update(dns_data)
        dns_questions, offset_pointer = self.decode_question_section(data, 20, dns_data['total_questions'])
        if dns_data['total_answers_rr']:
            answers_dict, offset_pointer = self._unpack_dns_rr(data, offset_pointer, dns_data['total_answers_rr'])
            dns_dict.update({'answer':answers_dict})
        if dns_data['total_authority_rr']:
            pass
        if dns_data['total_additional_rr']:
            additional_dict, offset_pointer = self._unpack_dns_additional_rr(data, offset_pointer, dns_data['total_additional_rr'])
            dns_dict.update({'additional_answer':additional_dict})
        # build the return data
        return dns_dict
        
        
