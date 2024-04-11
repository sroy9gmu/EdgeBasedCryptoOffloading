import sys
sys.path.append('/home/sunanda/Downloads/tee_sgx/edge_offload/v4')
import socket
import time
from multiprocessing import Process
import os
import subprocess
import sys
from key_exchange.symmetric import AESCipher

HOST = '192.168.1.202'
PORT = 37020
SIZE_BUFF = 1024
NUM_ROUNDS = 1
FILE_CLIENT = 'client-file'
PT = FILE_CLIENT + '.txt'
CT = PT + '.cpabe'  
aes_key_file = 'key256.txt'
aes_key_length = 32
ct_aes = {'32' : 88, '512' : 728, '1024' : 1408, '2048' : 2776} 
ct_cpabe = {'32' : 897, '512' : 1377, '1024' : 1889, '2048' : 2913}
ct_openabe = {'32' : 882, '512' : 1522, '1024' : 2206, '2048' : 3570}

class Server:

    def __init__(self, is_enc, do_tee, cp_abe, pt_b):
        self.is_enc = is_enc
        self.do_tee = do_tee
        self.cp_abe = cp_abe
        self.pt_b = int(pt_b)

        self.cmd_cleanup = 'rm *key *cpabe ' + FILE_CLIENT + '*'

        fp = open(aes_key_file)
        self.aes_key = fp.read()
        fp.close()

        if self.cp_abe == 1:
            self.ct_b = ct_cpabe[pt_b]
            self.cmd_setup = 'cpabe-setup'
            self.cmd_keygen_i = 'cpabe-keygen -o sai_priv_key pub_key master_key temperature humidity'
            self.cmd_enc = "cpabe-enc pub_key " + PT + " 'temperature and humidity'"
            self.cmd_dec_i = 'cpabe-dec pub_key sai_priv_key ' + CT
        else:
            self.ct_b = ct_openabe[pt_b]
            self.cmd_setup = 'oabe_setup -s CP'
            self.cmd_keygen_i = 'oabe_keygen -s CP -i "temperature|humidity" -o sai_priv'
            self.cmd_enc = 'oabe_enc -s CP -e "temperature and humidity" -i ' + PT + ' -o ' + CT
            self.cmd_dec_i = 'oabe_dec -s CP -k sai_priv.key -i ' + CT + ' -o ' + PT

        self.cmd_setup_sgx = 'gramine-sgx ' + self.cmd_setup
        self.cmd_keygen_i_sgx = 'gramine-sgx ' +  self.cmd_keygen_i
        self.cmd_enc_sgx = 'gramine-sgx ' + self.cmd_enc
        self.cmd_dec_i_sgx = 'gramine-sgx ' + self.cmd_dec_i

        print("Removing old outputs")
        subprocess.run(self.cmd_cleanup, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if self.is_enc == True:            
            if self.do_tee == True:
                print("Start of setting up keys (inside enclave)")  
                subprocess.run(self.cmd_setup_sgx, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(self.cmd_keygen_i_sgx, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("End of setting up keys (inside enclave)\n")  
            else:
                print("Start of setting up keys (outside enclave)")  
                subprocess.run(self.cmd_setup, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(self.cmd_keygen_i, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print("End of setting up keys (outside enclave)\n")   

    def attach_to_client(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            conn = None
            while not conn:
                print("Waiting to receive data from client")
                conn, addr = s.accept()
            ptorg = 'pt' + str(self.pt_b) + '.txt' 
            if self.is_enc == True:
                print("Number of iterations = {}\n".format(NUM_ROUNDS))
                print("Receive AES encrypted plaintext from client and decrypt it")
                for i in range(NUM_ROUNDS):
                    tmp = conn.recv(SIZE_BUFF) # START TIME
                    line = tmp                      
                    while tmp:
                        if len(line) >= ct_aes[str(self.pt_b)]:
                            break
                        tmp = conn.recv(SIZE_BUFF) 
                        line += tmp                        
                    obj = AESCipher(self.aes_key, aes_key_length)
                    line_org = obj.decryptCBC(line)
                    length = 0
                    with open(PT, 'wb') as f:
                        while line_org:
                            f.write(line_org.encode('utf-8'))
                            length += len(line_org)
                            if length >= self.pt_b:
                                break
                            line = conn.recv(SIZE_BUFF)
                            obj = AESCipher(self.aes_key, aes_key_length)
                            line_org = obj.decryptCBC(line)                    
                    if self.do_tee == True:                    
                        subprocess.run(self.cmd_enc_sgx, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)                             
                    else:
                        subprocess.run(self.cmd_enc, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)              
                    with open(CT, 'rb') as f:           
                        line = f.read(self.ct_b)
                        conn.sendall(line)   # END TIME                  
                    ctnew = CT + '.' + str(i)
                    os.rename(CT, ctnew)
                print("Send ABE ciphertext to client\n")                  

                print("Start of encryption check")
                err = False
                for i in range(NUM_ROUNDS): 
                    ctnew = CT + '.' + str(i)
                    os.rename(ctnew, CT) 
                    subprocess.run(self.cmd_dec_i, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
                    with open(PT, 'rb') as f:
                        line = f.read()                                     
                    with open(ptorg, 'rb') as f:
                        line1 = f.read()
                    if line != line1:
                        print('decryption error in round', i, line, line1)
                        err = True
                if not err:
                    print("Decryption of all ciphertexts matches with plaintext")  
                print("End of encryption check\n")                  
            else:     
                print("Receive ABE ciphertext from client and decrypt it")  
                for i in range(NUM_ROUNDS):
                    length = 0
                    line = conn.recv(SIZE_BUFF)
                    with open(CT, 'wb') as f:
                        while line:
                            f.write(line)
                            length += len(line)
                            if length >= self.ct_b:
                                break
                            line = conn.recv(SIZE_BUFF) 
                    if self.do_tee == True:
                        subprocess.run(self.cmd_dec_i_sgx, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
                    else:                                                     
                        subprocess.run(self.cmd_dec_i, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)                                                   
                    with open(PT, 'r') as f:           
                        line = f.read(self.pt_b) 
                        obj = AESCipher(self.aes_key, aes_key_length)
                        aes_ct = obj.encryptCBC(line)                       
                        conn.sendall(aes_ct)                                 
                    ptnew = PT + '.' + str(i)
                    os.rename(PT, ptnew)  
                print("Send AES encrypted plaintext to client")                   

                err = False
                for i in range(NUM_ROUNDS): 
                    ptnew = PT + '.' + str(i)
                    with open(ptnew, 'rb') as f:
                        line = f.read()                                     
                    with open(ptorg, 'rb') as f:
                        line1 = f.read()
                    if line != line1:
                        print('decryption error in round', i, line, line1) 
                        err = True
                if not err:
                    print("All decrypted outputs match with plaintext") 
            
    def create(self):
        self.p = Process(target=self.attach_to_client, args=(''))
        
    def run(self):
        self.p.start()
        self.p.join()
        self.p.close()
        
                   
