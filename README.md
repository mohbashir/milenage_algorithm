# milenage_algorithm
-----------------------------------   USIM Session     ----------------------------------

[SELECT]
I: 00 A4 00 04 02 3F 00 
O: 61 25 

[SELECT]
I: 00 A4 04 0C 02 A0 00 
O: 90 00 

[VERIFY CHV]
I: 00 20 00 81 08 30 30 30 30 FF FF FF FF 
O: 90 00 

[RUN GSM ALGORITHM]
I: 00 88 00 81 22 10 3D 8F FB 73 9D C7 18 3D 46 E6 EB 2E A7 6A 69 2F 10 B1 BD F7 AB 32 25 01 01 B4 53 0E 20 C3 3F A9 84 
O: 61 35 

[GET RESPONSE]
I: 00 C0 00 00 35 
O: DB 08 45 FE 85 E4 E3 53 CC 9C 10 8E 75 68 D5 79 3C 1E E1 F5 C3 21 39 AF CF 97 65 10 87 D8 3F F5 AA 51 CA CE 48 C2 10 15 46 9A 68 18 08 B4 AC 66 0C 3A 38 2B 52 90 00 

[RUN GSM ALGORITHM]
I: 00 88 00 81 22 10 3D 8F FB 73 9D C7 18 3D 46 E6 EB 2E A7 6A 69 2F 10 B1 BD F7 AB 32 25 01 01 B4 53 0E 20 C3 3F A9 84 
O: 61 10 

[GET RESPONSE]
I: 00 C0 00 00 10 
O: DC 0E 5C 11 D4 65 EE A3 69 87 F6 59 EF 33 DA 76 90 00 

-----------------
Authenticate Cmd:
-----------------
    I: 00 88 00 81 22
		EVEN Instruction
	  	|     |  Command Data Length
	  	|     1000 0001
	  	|     |     <-> 
	  	|     |      3G Context (if service 27 is avialable in UST so Kc would be calculated if the command succeeded)
	  	|		Specific reference data (e.g. DF specific/application dependant key)
	  
10 --> length of TEMP
3D8FFB739DC7183D46E6EB2EA76A692F --> RAND
10 --> length of AUTN
B1BDF7AB32250101B4530E20C33FA984 --> AUTN

-----------------
Get Response: (RES,CK,IK,Kc)
-----------------
DB --> Successful 3G Authentication Tag
08 --> Length of RES
45FE85E4E353CC9C --> RES
10 --> Length of CK
8E7568D5793C1EE1F5C32139AFCF9765 --> CK --> Cipher Key
10 --> Length of IK
87D83FF5AA51CACE48C21015469A6818 --> IK --> Itegrity Key
08 --> length of Kc
B4AC660C3A382B52 --> Kc --> GSM Response Parameter

but if we used the same SQN and the same RAND and sent the same Authenticate Command again, the authentication would fail:
-----------------
Get Response: (AUTS)
-----------------
DC --> "Synchronisation failure" tag
0E --> Length of AUTS
5C11D465EEA36987F659EF33DA76 --> AUTS
