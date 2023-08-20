from utils import *
class Milenage:
    def __init__(self, ki, opc, rand):
        #miliange constant
        self.c1 = bytes.fromhex('00000000000000000000000000000000')
        self.c2 = bytes.fromhex('00000000000000000000000000000001')
        self.c3 = bytes.fromhex('00000000000000000000000000000002')
        self.c4 = bytes.fromhex('00000000000000000000000000000004')
        self.c5 = bytes.fromhex('00000000000000000000000000000008')
        self.r1 = 64
        self.r2 = 0
        self.r3 = 32
        self.r4 = 64
        self.r5 = 96
        self.SQN = '000000011100'
        self.AMF = '0101'

        self.KI = ki
        self.OPc = opc
        self.RAND = rand


    def calculateMileange(self):
        #1- concatenate SQN || AMF || SQN || AMF
        IN1 = bytes.fromhex(self.SQN + self.AMF + self.SQN + self.AMF)

        #2- RAND ^ OPc
        RAND_xor_OPc = xor(RAND, OPc)
        print("RAND ^ OPc : ", RAND_xor_OPc.hex())

        #3- E[RAND ^ OPc]k --> encrypt the xor result with KI using Aes.ECB
        TEMP = aes_encrypt(RAND_xor_OPc, KI)
        print("(E[RAND ^ OPc]k) : ", TEMP.hex())

        #--------------calculating MAC-A----------------
        #4- E[TEMP ^ rot(IN1 ^ OPc, r1) ^ c1]k ^ OPc -->
        #4.1 IN1 ^ OPc
        IN1_xor_OPc = xor(IN1, OPc)
        print("IN1 ^ OPc : ",IN1_xor_OPc.hex())

        #4.2- rot(IN1 ^ OPc, r1) --> right rotate number of bit r1
        rotate_r1 = right_rotate(IN1_xor_OPc, self.r1)

        #4.3- TEMP ^ rot(IN1 ^ OPc, r1)
        out1 = xor(TEMP, rotate_r1)
        print('TEMP ^ rot(IN1 ^ OPc, r1) : ', out1.hex())

        #4.4- TEMP ^ rot(IN1 ^ OPc, r1) ^ c1
        out2 = xor(out1, self.c1)
        print('TEMP ^ rot(IN1 ^ OPc, r1) ^ c1 : ', out2.hex())

        #4.5- E[TEMP ^ rot(IN1 ^ OPc, r1) ^ c1]k --> encrypt out2 with KI using Aes.ECB
        TEMP2 = aes_encrypt(out2, KI)
        print('E[TEMP ^ rot(IN1 ^ OPc, r1) ^ c1]k : ', TEMP2.hex())

        #4.6- E[TEMP ^ rot(IN1 ^ OPc, r1) ^ c1]k ^ OPc --> xor with OPc
        OUT1 = xor(TEMP2, OPc)
        print('TEMP ^ rot(IN1 ^ OPc, r1) : ', OUT1.hex())
        MAC = OUT1[0:8] # MAc is first 8 bytes
        print("MAC-A : ", MAC.hex())

#-------------calculate Authentication Token, Anonymity key -------------------
        #5.1- TEMP ^ OPc
        TEMPxorOPc = xor(TEMP, OPc)
        print('TEMP ^ OPc : ', TEMPxorOPc.hex())

        #5.2- rot(TEMP ^ OPc, r2)
        rotate_r2 = right_rotate(TEMPxorOPc, self.r2) #right rotate with r2 number of bit

        #5.3- rot(TEMP ^ OPc, r2) ^ c2
        xor_c2 = xor(rotate_r2, self.c2)
        print('rot(TEMP ^ OPc, r2) ^ c2 : ', xor_c2.hex())

        #5.4- E[rot(TEMP ^ OPc, r2) ^ c2]k
        OUT2 = aes_encrypt(xor_c2, KI)
        OUT2 = xor(OUT2, OPc)
        print('E[rot(TEMP ^ OPc, r2) ^ c2]k : ', OUT2.hex())


        #--------------AUTN, RES AUTN-------
        AK = OUT2[0:6]
        RES = OUT2[8:]

        #5.5- AUTN = SQN ^ Ak || AMF || MAC
        AUTN = xor(bytes.fromhex(self.SQN), AK) + bytes.fromhex(self.AMF) + MAC

        #------Authenticate command variable------------
        print('RAND : ', RAND.hex())
        print('AUTN : ', AUTN.hex())
        print('AK  : ', AK.hex())
        print('SRES : ', RES.hex())

        return AUTN
        # build the Authenticate Command


        auth_cmd =build_auth_command(self.RAND, self.AUTN)


KI = bytes.fromhex('701DF4E9E28495A12B66F3E28F79F514')
OPc  = bytes.fromhex('51D57165499A6EAA8F7EE6642EB7FF15')
RAND = bytes.fromhex('3D8FFB739DC7183D46E6EB2EA76A692F')

milenage = Milenage(KI, OPc, RAND)
AUTN = milenage.calculateMileange()

authen_cmd = build_auth_command(RAND, AUTN)
print(authen_cmd.hex())

'''
response APDU from authentication command(RUN GSM ALGORITHM) 
DB 08 0BA9F9AD41356740 10 E194C2D279A6B623FCA2DA0B5E193ADD 10 43A5084A4B953A7D443573E88C2D3507 08 1A A6 63 7B E0 07 83 84 90 00 

Get Response: (RES,CK,IK,Kc)
-----------------
DB --> Successful 3G Authentication Tag
08 --> Length of RES
0BA9F9AD41356740 --> RES
10 --> Length of CK
E194C2D279A6B623FCA2DA0B5E193ADD --> CK --> Cipher Key
10 --> Length of IK
43A5084A4B953A7D443573E88C2D3507 --> IK --> Itegrity Key
08 --> length of Kc
1AA6637BE0078384 --> Kc --> GSM Response Parameter
'''