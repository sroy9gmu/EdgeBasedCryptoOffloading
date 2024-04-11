import sys
sys.path.append('/home/sunanda/Downloads/tee_sgx/edge_offload/v4')
from key_exchange.server import Server
from key_exchange.client import Client
from statistics import geometric_mean
import subprocess
import time
import os
import filecmp
import shutil
import socket
import json
from key_exchange.symmetric import AESCipher
from statistics import geometric_mean
import os.path

# Numbers
# No offload : reqs - 10, abd - 300
# Offload Hsu : reqs - 300, aes - 20000, abd - 700
# Offload Proposed : reqs - 400, aes - 20000, abd - 1000

class Edge:

    def __init__(self, args_file):
        with open(args_file) as f:
            self.args_dict = json.load(f)
            self.size_buff= 1024        

    def do_aes_abe(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.devi["host_ip"], int(self.devi["port_offload"])))
            s.listen()
            conn = None
            while not conn:
                # print("\n~~~Waiting to receive ABE input from Di~~~")
                conn, addr = s.accept()
                for i in range(self.num_req):
                    # if i == 0:
                    #     print("START: Received ABE input {} from Di and perform ABE".format(i + 1))
                    line = conn.recv(int(self.devi["aes_ciphertext_size"]))                                      
                    self.aes_ct = line                
                    with open(self.devi["aes_key_file"]) as f:
                        self.aes_key = f.read()
                    obj = AESCipher(self.aes_key, int(self.devi["aes_key_size"]))
                    self.aes_pt = obj.decryptCBC(self.aes_ct)
                    with open(self.pti_file, 'w') as f:
                        f.write(self.aes_pt)

                    subprocess.run(self.cmd_setup, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(self.cmd_keygen_a, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    subprocess.run(self.send_keys_peer, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

                    if self.devi["do_tee"] == "1":                    
                        subprocess.run(self.cmd_enc_sgx, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)                             
                    else:
                        subprocess.run(self.cmd_enc, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 
                    # if i == self.num_req - 1:
                    #     print("END: Received ABE input {} from Di and perform ABE".format(i + 1))

            if self.devi["do_opt"] == "0":
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                    conn.connect((self.endi_ip, int(self.endi_port)))                
                    with open(self.cti_file, 'rb') as f:           
                        line = f.read()
                        for i in range(self.num_req):
                            # if i == 0:
                            #     print("\nSTART: Sending ABE output {} to Di".format(i + 1))
                            conn.sendall(line)
                            # if i == self.num_req - 1:
                            #     print("END: Sending ABE output {} to Di".format(i + 1))
            else:
                # print("ASSUMPTION: SAj has received ABE output from SAi on the same device (made a copy)")   
                shutil.copyfile(self.cti_file, self.ctj_file)              

    def do_abd_aes(self):        
        if self.devj["do_opt"] == '0':
            copy_times = []
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.devj["host_ip"], int(self.devj["port_offload"])))
                s.listen()
                conn = None
                while not conn:
                    conn, addr = s.accept()                    
                    for i in range(self.num_abd):
                        # if i == 0:
                        #     print("\nSTART: Receive ABD input from Dj and send encrypted ABD output {} to Dj".format(i + 1))                             
                        line = conn.recv(int(self.devj["abe_ciphertext_size"]))                      
                        with open(self.ctj_file, 'wb') as f:
                            f.write(line)

                        start1 = time.time()
                        if not os.path.isfile(self.ctj_file + ".bak"):
                            shutil.copyfile(self.ctj_file, self.ctj_file + ".bak")
                        end1 = time.time()

                        if self.devj["do_tee"] == "1":                    
                            subprocess.run(self.cmd_dec_a_sgx, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)                             
                        else:       
                            subprocess.run(self.cmd_dec_a, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 

                        start2 = time.time()
                        shutil.copyfile(self.ctj_file + ".bak", self.ctj_file) 
                        end2 = time.time()

                        copy_times.append((end2 - start2) + (end1 - start1))
            
                        obj = AESCipher(self.aes_key, int(self.devj["aes_key_size"]))
                        with open(self.ptj_file, 'r') as f:   
                            self.aes_ct = obj.encryptCBC(f.read())
                        conn.sendall(self.aes_ct)
                        # if i == self.num_abd - 1:
                        #     print("END: Receive ABD input from Dj and send encrypted ABD output {} to Dj".format(i + 1)) 
                    print("Mean copy time - {} microseconds".format(geometric_mean(copy_times) * 1000000))
        else:            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.connect((self.endj_ip, int(self.endj_port)))   
                copy_times = []   
                shutil.copyfile(self.ctj_file, self.ctj_file + ".bak")            
                for i in range(self.num_abd):
                    if i == 0:
                        print("\nSTART: Send encrypted ABD output to Dj - ", time.asctime()) 
                        print(time.time())                           

                    if self.devj["do_tee"] == "1":                    
                        subprocess.run(self.cmd_dec_a_sgx, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)                             
                    else:
                        subprocess.run(self.cmd_dec_a, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) 

                    start = time.time()
                    shutil.copyfile(self.ctj_file + ".bak", self.ctj_file) 
                    end = time.time() 
                    copy_times.append(end - start)

                    obj = AESCipher(self.aes_key, int(self.devj["aes_key_size"]))
                    with open(self.ptj_file, 'r') as f:   
                        self.aes_ct = obj.encryptCBC(f.read())        

                    conn.sendall(self.aes_ct)
                    # if i == self.num_abd - 1:
                    #     print("\nEND: Send encrypted ABD output to Dj")  
                print("Mean copy time - {} microseconds".format(geometric_mean(copy_times) * 1000000))                          
 
    def parse_args(self):
        err = False

        devs = self.args_dict["settings"]["devices"]

        for dev in devs:
            if dev["id"] == "SAi":
                self.devi = dev
                self.cti_file = dev["plaintext_file"] + ".cpabe"
                self.pti_file = dev["plaintext_file"]
                self.num_req = int(dev["num_req"])
                self.abe_lib = dev["abe_lib"]

            if dev["id"] == "SAj":
                self.devj = dev
                self.peer_ip = dev["host_ip"]
                self.peer_port = dev["port_data"]
                self.peer_dir = dev["workdir"]
                self.ctj_file = dev["plaintext_file"] + ".cpabe"
                self.ptj_file = dev["plaintext_file"]
                self.num_abd = int(dev["num_abd"])
                self.num_aes = int(dev["num_aes"])

            if dev["id"] == "Di":
                self.endi_ip = dev["host_ip"]
                self.endi_port = dev["port_offload"]

            if dev["id"] == "Dj":
                self.endj_ip = dev["host_ip"]
                self.endj_port = dev["port_offload"]

    def get_cmds(self):
        if self.abe_lib == "cpabe":            
            self.cmd_setup = 'cpabe-setup'
            self.cmd_keygen_a = 'cpabe-keygen -o a_priv_key pub_key master_key temperature humidity'
            self.cmd_keygen_b = 'cpabe-keygen -o b_priv_key pub_key master_key pressure humidity'
            self.cmd_enc = "cpabe-enc pub_key " + self.pti_file + " 'temperature and humidity'"            
            self.cmd_dec_a = 'cpabe-dec pub_key a_priv_key ' + self.ctj_file
            self.send_keys_peer = "sshpass -p " + self.devi["scp_pwd"] + "scp pub_key a_priv_key sunanda@" + self.peer_ip + ":" + self.peer_dir
        else:
            self.cmd_setup = 'oabe_setup -s CP'
            self.cmd_keygen_a = 'oabe_keygen -s CP -i "temperature|humidity" -o a_priv'
            self.cmd_keygen_b = 'oabe_keygen -s CP -i "pressure|humidity" -o b_priv'
            self.cmd_enc = 'oabe_enc -s CP -e "temperature and humidity" -i ' + self.pti_file + ' -o ' + self.cti_file            
            self.cmd_dec_a = 'oabe_dec -s CP -k a_priv.key -i ' + self.ctj_file + " -o " + self.ptj_file
            self.send_keys_peer = "sshpass -p " + self.devi["scp_pwd"] + "scp mpk.cpabe a_priv.key sunanda@" + self.peer_ip + ":" + self.peer_dir


def main():
    edg = Edge(sys.argv[1])
    edg.parse_args()
    edg.get_cmds()

    # print("\n********EDGE DEVICE: SAi********")
    edg.do_aes_abe()

    # print("\n********EDGE DEVICE: SAj********")
    edg.do_abd_aes()    

if __name__ == '__main__':
    main()
