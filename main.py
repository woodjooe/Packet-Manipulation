#!/usr/bin/python3

from RSA_enc import *
from socket_testing import *
import argparse
import os as _os
import sys as _sys
import struct


def packet_crafting(encrypted_smtp):


	# Define the Ethernet, IP, and UDP headers
	ethernet_header = struct.pack('!6s6sH', b'\xaa\xaa\xaa\xaa\xaa\xaa', b'\xbb\xbb\xbb\xbb\xbb\xbb', 0x0800)
	ip_header = struct.pack('!BBHHHBBH4s4s', 0x45, 0x00, 0x001e, 0x0000, 0x4000, 0x40, 0x06, 0x0000, b'\x7f\x00\x00\x01', b'\x7f\x00\x00\x01')
	udp_header = struct.pack('!HHHH', 4242, 4242, 0x0000, 0x0000)


	# Concatenate the headers and message to create the packet
	packet = ethernet_header + ip_header + udp_header + encrypted_smtp
	
	return packet

if __name__ == '__main__':
	'''
	if _os.geteuid():
		_sys.exit('listener must be ran as root! exiting...')

	sniff.listen_forever('lo')
	'''
	
	parser = argparse.ArgumentParser(description='RSA reader')
	parser.add_argument('-m', metavar=',--Message ',
                            help=' Message to encrypt ', required=True)
	args = parser.parse_args()
	msg = args.m
	
	smtp_body = 'From: datboi@weew.com\r\nTo: recipient@weew.com\r\nSubject: the goods\r\n\r\n'+ msg +'.\r\n'
	smtp_message = ('HELO example.com\r\nMAIL FROM: sender@example.com\r\nRCPT TO: recipient@example.com\r\nDATA\r\n' + smtp_body + '.\r\nQUIT\r\n')
	
	RSA = mainRSA(smtp_message)
	
	Encrypted_smtp1 = RSA[0]  # Comes out as bytes
	Encrypted_smtp2 = RSA[1]
	RSA_E = long_to_bytes(RSA[2])
	RSA_N = long_to_bytes(RSA[3])
	
	lines = [RSA_N, RSA_E, Encrypted_smtp1, Encrypted_smtp2]
	
	with open('N_E_C1_C2.txt', 'wb') as file:
		for line in lines:
			file.write(line+b'\n')
	

	
	packet = PacketManipulation(('127.0.0.1', 4242))
	
	data = packet_crafting(Encrypted_smtp1)
	packet.send_to(data)
	
	data = packet_crafting(Encrypted_smtp2)
	packet.send_to(data)
	
	


	
