import os
import sys
import json

from dns_packet import dns_struct

d = dns_struct.dns_decode_struct()
d2 = dns_struct.dns_encode_struct()
p = 1
p2 = 2
p3 = 3
p4 = 4
d2.pack_udp(p, p2, p3, p4)

# import socket
# s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW ,socket.ntohs(0x0003))
# while True:
# 	try:
# 	    packet, addr = s.recvfrom(65565)
# 	    print type(packet)
# 	    print "received message:"
# 	    # 42 for real value
# 	    dp =  d.unpack_dns(packet[34:])
# 	    print json.dumps(dp, sort_keys=True, indent=2)
# 	    #print dp
# 	except Exception as e:
# 		print e
# 		pass

