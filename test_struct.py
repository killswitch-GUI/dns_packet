import os
import sys
import json

from dns_packet import dns_struct

d = dns_struct.dns_decode_struct()
import socket
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW ,socket.ntohs(0x0003))
while True:
	try:
	    packet, addr = s.recvfrom(65565)
	    print "received message:"
	    # 42 for real value
	    dp =  d.unpack_dns(packet[34:])
	    print json.dumps(dp, sort_keys=True, indent=2)
	    #print dp
	except Exception as e:
		print e
		pass


s = dns_struct.dns_struct()
byte = b'01'
s._unpack_dns_upper_codes(byte)
s._unpack_dns_lower_codes(byte)

byte = bytearray(b'053130373030076d616c776172650c646566656e73652d6e657773036e657400')
s.decode_question_section(byte, 0, 1)
