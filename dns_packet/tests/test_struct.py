import os
import sys

from dns_packet import dns_struct
from dns_packet import dns_helpers
import struct


def test_helpers():
	# test helpers class
	d = dns_helpers.byte_opperations()
	assert d.hex_to_binary('1E') == '00011110'
	assert d.byte_to_hex('jj') == '6A 6A'

def test_dns_unpack():
	d = dns_struct.dns_decode_struct()
	data = 'string'
	sport = 4711    # arbitrary source port
	dport = 45134   # arbitrary destination port
	length = 8+len(data);
	checksum = 0
	udp_header = struct.pack('!HHHH', sport, dport, length, checksum)
	udp_ret = d.unpack_udp(udp_header)
	assert udp_ret['src_port'] == sport
	assert udp_ret['dst_port'] == dport
	assert udp_ret['length'] == length
	assert udp_ret['check_sum'] == checksum
