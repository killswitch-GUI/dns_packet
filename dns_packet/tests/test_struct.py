import os
import sys

from dns_packet import dns_struct
from dns_packet import dns_helpers


def test_helpers():
	# test helpers class
	d = dns_helpers.byte_opperations()
	
	assert d.hex_to_binary('0101') == 5 
