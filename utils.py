from smartcard.util import toBytes, toHexString
from Crypto.Cipher import DES3, DES, AES
import collections
from smartcard.System import readers
from smartcard.sw.SWExceptions import CheckingErrorException
def xor(byte_1, byte_2):
    return bytes([b1 ^ b2 for b1, b2 in zip(byte_1, byte_2)])

def aes_encrypt( message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(message)

def right_rotate(byte_ar, num_bit):
    x = collections.deque(byte_ar)
    x.rotate(int(num_bit / 8))

    return list(x)

def build_auth_command(RAND, AUTN):
    cmd = bytes([0x00,0x88,0x00,0x81])
    return cmd + bytes([len(RAND)]) + RAND + bytes([len(AUTN)]) + AUTN

