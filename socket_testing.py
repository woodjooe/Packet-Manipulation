#!/usr/bin/env python3

from ipaddress import IPv4Address
from enum import IntEnum

from socket import socket, AF_INET, SOCK_DGRAM


class PROTO(IntEnum):
    TCP = 6
    UDP = 17


class PacketManipulation:

    #class to manipulate tcp/ip packets. currently limited to UDP only!.

    __slots__ = ( # slots make things faster. just do them. :)
        'target', 'data', 'protocol', 'socket',

        'connect'
    )

    def __init__(self, target, *, protocol=PROTO.UDP):
    
        self.target = target
        self.connect = False
	
        if  target:
            self._validate_target()
            self.create_socket()	# => connect = True and creates socket
        else:
            self.create_socket(True)
	    
        self.socket = socket() 
        
        self.protocol = PROTO.UDP	# Uses udp only for now
        
        self.create_socket()

    def create_socket(self, *, connect=False):
        self.socket = socket(AF_INET, SOCK_DGRAM)

        if connect:
            self.socket.connect(self.target)

            self.connect = True

    def send(self, data):
        
        if not self.connect:
            raise RuntimeError('cannot call send method without connect argument in socket creation.')

        if not isinstance(data, bytes):
            raise TypeError('data must be a bytestring.')

        sent_count = self.socket.send(data)

        print(f'sent {sent_count} bytes!')

    def send_to(self, data, *, target=None):

        if not isinstance(data, bytes):
            raise TypeError('data must be a bytestring.')

        if not target:
            target = self.target

            self._validate_target(target)

        sent_count = self.socket.sendto(data, target)

        print(f'sent {sent_count} bytes!')

    def _validate_target(self, target=None):
        if target is None:
            target = self.target

        if not isinstance(target, tuple) or len(target) != 2:
            raise TypeError('target must be a two tuple containing host ip/port.')

        try:
            IPv4Address(target[0])
        except:
            raise ValueError('invalid ip address provided for target.')

        if not isinstance(target[1], int):
            raise TypeError('target port must be an integer.')

        if not target[1] in range(0, 65536):
            raise ValueError('target port must be between 0-63535')



