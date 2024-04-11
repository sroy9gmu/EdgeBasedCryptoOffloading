import sys
sys.path.append('/home/sunanda/Downloads/tee_sgx/edge_offload/v4')
import socket
import time
from multiprocessing import Process
import os
from statistics import geometric_mean
import subprocess
from key_exchange.symmetric import AESCipher

HOST = '192.168.1.202'
DESTDIR = "/home/sunanda/Downloads/tee_sgx/edge_offload/v4/data_exchange"
PORT = 37020
durs = []
durs_recv = []
NUM_ROUNDS = 10
SIZE_BUFF = 1024
aes_key_file = 'key256.txt'
aes_key_length = 32
ct_aes = {'32' : 88, '512' : 728, '1024' : 1408, '2048' : 2776} 
ct_cpabe = {'32' : 897, '512' : 1377, '1024' : 1889, '2048' : 2913}
ct_openabe = {'32' : 882, '512' : 1522, '1024' : 2206, '2048' : 3570}

class Client:

    def __init__(self, is_enc, do_tee, cp_abe, pt_b):        
        self.is_enc = is_enc
        self.do_tee = do_tee
        self.cp_abe = cp_abe

        self.pt_dec = 'pt' + pt_b + '.txt'
        self.ct = 'pt' + pt_b + '.txt.cpabe'
        self.pt_b = int(pt_b)

        self.cmd_cleanup = 'rm *key *cpabe'

        fp = open(aes_key_file)
        self.aes_key = fp.read()
        fp.close()

        fp = open(self.pt_dec)
        self.pt = fp.read()
        fp.close()

        if self.cp_abe == 1:
            self.ct_b = ct_cpabe[pt_b]
            self.cmd_setup = 'cpabe-setup'
            self.cmd_keygen_i = 'cpabe-keygen -o sai_priv_key pub_key master_key temperature humidity'
            self.cmd_enc = "cpabe-enc pub_key " + self.pt_dec + " 'temperature and humidity'"
        else:
            self.ct_b = ct_openabe[pt_b]
            self.cmd_setup = 'oabe_setup -s CP'
            self.cmd_keygen_i = 'oabe_keygen -s CP -i "temperature|humidity" -o sai_priv'
            self.cmd_enc = 'oabe_enc -s CP -e "temperature and humidity" -i ' + self.pt_dec + ' -o ' + self.ct

        if self.cp_abe == True:
            self.scp_keys_abe = "scp *key* sunanda@" + HOST + ":" + DESTDIR       
        else:
            self.scp_keys_abe = "scp *key* m* sunanda@" + HOST + ":" + DESTDIR
        
        print("Removing old outputs")
        subprocess.run(self.cmd_cleanup, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not self.is_enc:            
            print("Start of setting up ABD keys")  
            subprocess.run(self.cmd_setup, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(self.cmd_keygen_i, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("End of setting up ABD keys\n")
            print("Start of sending ABD keys to EDGE device")
            subprocess.run(self.scp_keys_abe, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("End of sending ABD keys to EDGE device\n")

    def attach_to_server(self):        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.connect((HOST, PORT))
            if self.is_enc == True:
                print("Number of iterations = {}\n".format(NUM_ROUNDS))
                for i in range(NUM_ROUNDS):
                    length = 0
                    if i == 0:
                        print("Start time for all ABEs = {}\n".format(time.asctime()))
                        print("Send plaintext encrypted with AES-256-CBC cipher to server")
                    start = time.time()            
                    obj = AESCipher(self.aes_key, aes_key_length)
                    aes_ct = obj.encryptCBC(self.pt)
                    conn.sendall(aes_ct)                                                         
                    with open(self.ct, 'wb') as f:                     
                        msg = conn.recv(SIZE_BUFF)                      
                        while msg:
                            length += len(msg)
                            f.write(msg)
                            if length >= self.ct_b:
                                break                    
                            msg = conn.recv(SIZE_BUFF)                          
                    end = time.time()
                    if i == NUM_ROUNDS - 1:                        
                        print("End time for all ABEs = {}\n".format(time.asctime()))
                    durs.append(end - start)               
                print("Average duration (microseconds) = {}\n".format(1000000 * geometric_mean(durs)))
            else:                 
                subprocess.run(self.cmd_enc, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("Ciphertext generated for transmission to EDGE device")
                print("Number of iterations = ", NUM_ROUNDS)
                for i in range(NUM_ROUNDS):                    
                    if i == 0:
                        print("Start time for all ABDs = ",time.asctime())
                    start = time.time()
                    with open(self.ct, 'rb') as f:
                        line = f.read(self.ct_b)
                        conn.sendall(line)  
                    with open(self.pt_dec, 'w') as f:
                        tmp = conn.recv(SIZE_BUFF)
                        msg = tmp                      
                        while tmp:
                            if len(msg) >= ct_aes[str(self.pt_b)]:
                                break
                            tmp = conn.recv(SIZE_BUFF) 
                            msg += tmp
                        obj = AESCipher(self.aes_key, aes_key_length)
                        msg_org = obj.decryptCBC(msg)
                        length = 0
                        while msg_org:
                            length += len(msg_org)
                            f.write(msg_org)
                            if length >= self.pt_b:
                                break                    
                            msg = conn.recv(SIZE_BUFF)  
                            obj = AESCipher(self.aes_key, aes_key_length)
                            msg_org = obj.decryptCBC(msg)                       
                    end = time.time()
                    if i == NUM_ROUNDS - 1:
                        print("End time for all ABDs = ",time.asctime())
                        print("Decrypt AES encrypted plaintext from server") 
                    durs.append(end - start)                        
                print("Average duration (microseconds) = ", 1000000 * geometric_mean(durs))

    def create(self):
        self.p = Process(target=self.attach_to_server, args=(''))
        
    def run(self):
        self.p.start()
        self.p.join()
        self.p.close()
                
                    
