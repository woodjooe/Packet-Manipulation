# Packet-Manipulation
Sniffing and manipulation of packets

Test code: <br>
#### 1) Start the sniffer, this will sniff the packet we send later on and save it in a pcap file. <br>
###### sudo python3 sniffer_testing.py <br>

#### 2) Send the packet enclosed in eth, ip, udp, smtp headers and encrypt it starting from the smtp header using RSA. save the public key in a file named N_E_C1_C2.txt <br>
###### python3 main.py -m message <br>

#### 3) Start decryption process using <br>
###### sage CopperSmithShortPadAttack.sage <br>

#### 4) Read the resulting plaintext of the decrypted SMTP header in the file named: Plain.txt
