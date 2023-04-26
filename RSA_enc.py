#!/usr/bin/python3

from Crypto.Util.number import getPrime, long_to_bytes, inverse
from os import urandom


class RSA:
    def __init__(self):
    	while(True):
            try:
                self.p = getPrime(1024)
                self.q = getPrime(1024)
                self.e = 3
                self.n = self.p * self.q
                self.d = inverse(self.e, (self.p-1)*(self.q-1))
                break
            except:
                pass
                
    def encrypt(self, data: bytes) -> bytes:
        pt = int(data.hex(), 16)
        ct = pow(pt, self.e, self.n)
        print(pt)
        print(ct)
        return long_to_bytes(ct)
    
    def decrypt(self, data: bytes) -> bytes:
        ct = int(data.hex(), 16)
        pt = pow(ct, self.d, self.n)
        return long_to_bytes(pt)

def mainRSA(msg):

    def pad(data: bytes) -> bytes:
        return data+urandom(16)
    crypto = RSA()
    msg = msg.strip().encode()
    Enc_Msg1 = crypto.encrypt(pad(msg))
    Enc_Msg2 = crypto.encrypt(pad(msg))
    print([int.from_bytes(Enc_Msg1), int.from_bytes(Enc_Msg2), crypto.e, crypto.n])
    return [Enc_Msg1, Enc_Msg2, crypto.e, crypto.n]

