#!/usr/bin/env python3

# The undescores are here to prevent namespace conflictions.
import os as _os
import sys as _sys
import time as _time
import socket as _socket
from scapy.all import wrpcap, Ether, IP, UDP, TCP, Raw

from struct import Struct as _Struct
from ipaddress import IPv4Address as _IPv4Address

# assigning variables to direct function references.
_fast_time = _time.time
_write_err = _sys.stdout.write

tcp_header_unpack = _Struct('!2H2LB').unpack_from
udp_header_unpack = _Struct('!4H').unpack_from


class RawPacket:
    '''tcp/ip packet represented in class form. packet fields can be accessed via their corresponding attribute.'''

    def __init__(self, data):
        self.timestamp = _fast_time()
        self.protocol  = 0

        self._name = self.__class__.__name__

        self._dlen = len(data)

        self.dst_mac = data[:6].hex()
        self.src_mac = data[6:12].hex()
        self.prot = int.from_bytes(data[12:14])
        self._data   = data[14:]


    def __str__(self):
        ch1='\n'+'\n'.join([
            f'{"="*32}',
            f'{" "*13}PACKET',
            f'{"="*32}',
            f'{" "*12}ETHERNET',
            f'{"-"*32}',
            f'src mac:             {self.src_mac}',
            f'dst mac:             {self.dst_mac}',
            f'protocol:            {self.prot}',
            f'{"-"*32}',
            f'{" "*14}IP',
            f'{"-"*32}',
            f'ip version:          {self.ip_version}',
            f'header length:       {self.ip_header_len}',
            f'type of service:     {self.ip_typeOfService}',
            f'data length:         {self.ip_data_len}',
            f'packet ID:           {self.ip_packet_ident}',
            f'D Flag:              {self.ip_DF}',
            f'M Flag:              {self.ip_MF}',
            f'ip fragment offset:  {self.ip_fragment_offset}',
            f'Time to Live:        {self.ip_TTL}',
            f'protocol:            {self.ip_protocol}',
            f'header checksum:     {self.ip_header_checksum}',
            f'src ip:              {self.ip_src}',
            f'dst ip:              {self.ip_dst}',
            f'{"-"*32}\n',
        ])
        if (self.ip_protocol == 6):
            ch2='\n'.join([
                f'{" "*12}PROTOCOL',
                f'{"-"*32}',
                f'src port:            {self.src_port}',
                f'dst port:            {self.dst_port}',
                f'sequence number:     {self.tcp_seq_number}',
                f'ack number:          {self.tcp_ack_number}',
                f'header length:       {self.tcp_header_len}',
                f'res:                 {self.tcp_res}',
                f'code type:           {self.tcp_code}',
                f'flags corresponding: {self.tcp_flags}',
                f'window size:         {self.tcp_window}',
                f'checksum:            {self.tcp_checkSum}',
                f'Urgent type:         {self.tcp_Urgent}',
                f'{"-"*32}',
                f'{" "*12}PAYLOAD',
                f'{"-"*32}',
                f'{self.payload}'
            ])
        elif (self.ip_protocol == 17):
            ch2='\n'.join([
                f'{" "*12}PROTOCOL',
                f'{"-"*32}',
                f'src port:            {self.src_port}',
                f'dst port:            {self.dst_port}',
                f'data length:         {self.udp_len}',
                f'checksum:            {self.udp_chk}',
                f'{"-"*32}',
                f'{" "*12}PAYLOAD',
                f'{"-"*32}',
                f'{self.payload}'
        ])
        return ch1 + ch2
            

    def parse(self):
        '''index tcp/ip packet layers 3 & 4 for use as instance objects.'''

        self._ip()
        if (self.ip_protocol == 6):
            self._tcp()

        elif (self.ip_protocol == 17):
            self._udp()

        else:
            _write_err('non tcp/udp packet!\n')

    def _ip(self):
        data = self._data
        self.ip_version = ((data[0] & 240) >> 4)
        self.ip_header_len = ((data[0] & 15) * 4)
        self.ip_typeOfService = (data[1])
        self.ip_data_len = int.from_bytes(data[2:4])
        self.ip_packet_ident = int.from_bytes(data[4:6])
        self.ip_DF = ((data[6] & 64) >> 6)
        self.ip_MF = ((data[6] & 32) >> 5)
        if (self.ip_DF):
            self.ip_flags="DF"
        elif (self.ip_MF):
            self.ip_flags="MF"
        else:
            self.ip_flags=""
        self.ip_fragment_offset = ((data[6] & 31) * pow(2,7) + data[7])
        self.ip_TTL = data[8]
        self.ip_protocol = data[9]
        self.ip_header_checksum = int.from_bytes(data[10:12])
        self.ip_src = _IPv4Address(data[12:16])
        self.ip_dst = _IPv4Address(data[16:20])

        self.ip_header = data[:self.ip_header_len]

        # removing ip header from data
        self._data = data[self.ip_header_len:]

    # tcp header max len 32 bytes
    def _tcp(self):
        data = self._data

        tcp_header = tcp_header_unpack(data)
        self.src_port   = tcp_header[0]
        self.dst_port   = tcp_header[1]
        self.tcp_seq_number = tcp_header[2]
        self.tcp_ack_number = tcp_header[3]
        self.tcp_header_len = (tcp_header[4] >> 4 & 15) * 4
        self.tcp_res = (((data[12] & 15) << 2) + (data[13] >> 6))
        self.tcp_code = (data[13] & 63)
        self.tcp_flags='b'
        for i in range(5,-1,-1):
            flags += str((self.tcp_code >> i)%2)
        
        if (flags[0]=='1'):
            self.tcp_flags+='U'
        if (flags[1]=='1'):
            self.tcp_flags+='A'
        if (flags[2]=='1'):
            self.tcp_flags+='P'
        if (flags[3]=='1'):
            self.tcp_flags+='R'
        if (flags[4]=='1'):
            self.tcp_flags+='S'
        if (flags[5]=='1'):
            self.tcp_flags+='F'
        
        self.tcp_window = (data[14])
        self.tcp_checkSum = (data[15])
        self.tcp_Urgent = (data[16])

        self.proto_header = data[:tcp_header_len]
        self.payload = data[tcp_header_len:]

    # udp header 8 bytes
    def _udp(self):
        data = self._data

        udp_header = udp_header_unpack(data)
        self.src_port = udp_header[0]
        self.dst_port = udp_header[1]
        self.udp_len  = udp_header[2]
        self.udp_chk  = udp_header[3]

        self.proto_header = data[:8]
        self.payload = data[8:]

def parse(data):

        packet = RawPacket(data)
        packet.parse()
        if not(packet.ip_protocol in [6,17]):
            return
        print('\n')
        print(packet)
        print('\n')
        
        msg = 'new changed message after interception' 
        
        eth = Ether(dst = "00:11:22:33:44:55", src = "66:77:88:99:aa:bb")
        ip  = IP(version = packet.ip_version, ihl = (packet.ip_header_len)//4,
              tos = packet.ip_typeOfService, len = packet.ip_data_len,
              id = packet.ip_packet_ident, flags = packet.ip_flags,
              frag = packet.ip_fragment_offset, ttl = packet.ip_TTL,
              proto = packet.ip_protocol, chksum = packet.ip_header_checksum,
              dst=packet.ip_dst, src=packet.ip_src)
        if (packet.ip_protocol == 6):
            tcp = TCP(sport = packet.src_port, dport = packet.dst_port,
                      seq = packet.tcp_seq_number, ack = packet.tcp_ack_number,
                      dataofs = (packet.tcp_header_len)//4, reserved = packet.tcp_res,
                      flags = packet.tcp_flags, window = packet.tcp_window,
                      chksum = packet.tcp_checkSum, urgptr = packet.tcp_Urgent)
                      
            pkt=eth/ip/tcp/Raw(load=packet.payload)
            
        elif (packet.ip_protocol == 17):
            udp = UDP(sport = packet.src_port, dport = packet.dst_port,
                      len = packet.udp_len, chksum = packet.udp_chk)
                      
            pkt=eth/ip/udp/Raw(load=packet.payload)


        # Open the existing pcap file in "append binary" mode
        with open('foo.pcap', 'ab') as f:
            wrpcap(f, pkt)
	
   
def listen_forever(intf):
    sock = _socket.socket(_socket.AF_PACKET, _socket.SOCK_RAW)
    try:
        sock.bind((intf, 3))
    except OSError:
        _sys.exit(f'cannot bind interface: {intf}! exiting...')
    else:
        _write_err(f'now listening on {intf}!')
        

    while True:
        try:
            data = sock.recv(2048)
        except OSError:
            pass

        else:
            parse(data)

if __name__ == '__main__':
    if _os.geteuid():
        _sys.exit('listener must be ran as root! exiting...')

    listen_forever('lo')
    

