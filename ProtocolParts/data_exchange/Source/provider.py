import sys
sys.path.append('/home/sunanda/Downloads/tee_sgx/edge_offload/v4')
import subprocess
import time
import os
import socket
import json
import shutil
from key_exchange.symmetric import AESCipher
from Crypto.Util.Padding import pad, unpad

class Provider:

    def __init__(self, args_file):
        # print("\n********END DEVICE: Di********")
        with open(args_file) as f:
            self.args_dict = json.load(f)
            self.size_buff = 1024

    def accept_data_request(self):        
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.dev["host_ip"], int(self.dev["port_data"])))
            s.listen()
            conn = None
            while not conn:
                # print("\n~~~Waiting to receive {} data requests~~~".format(self.num_req))
                conn, addr = s.accept()
                for i in range(self.num_req):
                    # if i == 0:
                    #     print("START: Data request {} received from Dj".format(i + 1))
                    tmp = conn.recv(1)
                    if tmp != b'1':
                        print("Error receiving data request {}, value = {}".format(i + 1, tmp))
                    # if i == self.num_req - 1:
                    #     print("END: Data request {} received from Dj".format(i + 1))

    def process_data_request(self):    
        if self.dev["do_offloading"] == '0':
            shutil.copyfile(self.pti_file, self.pti_file + ".bak")
            for i in range(self.num_req):
                # print("\n###Processing data request {}###".format(i + 1))
                
                # print("\nSTART: Setting up ABE keys on Di")
                subprocess.run(self.cmd_setup, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                subprocess.run(self.cmd_keygen_a, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # print("END: Setting up ABE keys on Di")

                # print("\nSTART: Send ABD keys to Dj")
                subprocess.run(self.send_keys_peer, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                # print("END: Send ABD keys to Dj")

                # print("\nSTART: Encrypting requested data using ABE")                
                subprocess.run(self.cmd_enc, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                shutil.copyfile(self.pti_file + ".bak", self.pti_file)
                # print("END: Encrypting requested data using ABE")
        else:
            for i in range(self.num_req):
                # if i == 0:
                #     print("\nSTART: Encrypt requested data {} with AES".format(i + 1))
                with open(self.dev["aes_key_file"]) as f:
                    self.aes_key = f.read()
                obj = AESCipher(self.aes_key, int(self.dev["aes_key_size"]))
                with open(self.pti_file, 'r') as f:
                    self.aes_ct = obj.encryptCBC(f.read())
                # if i == self.num_req - 1:
                #     print("END: Encrypt requested data {} with AES".format(i + 1))
        
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.connect((self.edge_ip, int(self.edge_port)))
                self.abe_ct = ''
                for i in range(self.num_req):
                    # if i == 0:
                    #     print("\nSTART: Send AES output {} to SAi".format(i + 1))
                    conn.sendall(self.aes_ct)
                    # if i == self.num_req - 1:
                    #     print("END: Send AES output {} to SAi".format(i + 1))

            if self.dev["do_opt"] == '0':                       
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind((self.dev["host_ip"], int(self.dev["port_offload"])))
                    s.listen()
                    conn = None                
                    while not conn:
                        conn, addr = s.accept()
                        self.abe_ct = ''
                        for i in range(self.num_req):
                            # if i == 0:
                            #     print("\nSTART: Receive ABE output {} from SAi".format(i + 1))                                            
                            line = conn.recv(int(self.dev["abe_ciphertext_size"])) 
                            if not self.abe_ct:
                                self.abe_ct = line                        
                            # if i == self.num_req - 1:
                            #     print("END: Receive ABE output {} from SAi".format(i + 1))
        self.ready_for_ack = False

    def send_processed_data(self): 
        if self.dev["do_offloading"] == '0':
            with open(self.cti_file, 'rb') as f:
                self.abe_ct = f.read()
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.connect((self.peer_ip, int(self.peer_port)))          
                for i in range(self.num_req):
                    # if i == 0:
                    #     print("\nSTART: Sending ABE output {} to Dj".format(i + 1))
                    conn.sendall(self.abe_ct) 
                    # if i == self.num_req - 1:
                    #     print("END: Sending ABE output {} to Dj".format(i + 1)) 
        elif self.dev["do_opt"] == '0':
            self.aes_abe_ct = ''
            for i in range(self.num_req):
                # if i == 0:
                #     print("\nSTART: Encrypt ABE output {} with AES".format(i + 1))
                with open(self.dev["aes_key_file"]) as f:
                    self.aes_key = f.read()
                obj = AESCipher(self.aes_key, int(self.dev["aes_key_size"]))
                ct = obj.encryptCBCbytes(pad(self.abe_ct, obj.block_size))     
                if not self.aes_abe_ct:
                    self.aes_abe_ct = ct
                # if i == self.num_req - 1:
                #     print("END: Encrypt ABE output {} with AES".format(i + 1))

            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                conn.connect((self.peer_ip, int(self.peer_port)))
                for i in range(self.num_req):
                    # if i == 0:
                    #     print("\nSTART: Sending encrypted ABE output {} to Dj".format(i + 1))
                    conn.sendall(self.aes_abe_ct)  
                    # if i == self.num_req - 1:
                    #     print("END: Sending encrypted ABE output {} to Dj".format(i + 1))
        self.ready_for_ack = True        

    def receive_acknowledgement(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((self.dev["host_ip"], int(self.dev["port_data"])))
            s.listen()
            conn = None
            while not conn:
                print("\n~~~Waiting to receive acknowledgement~~~")
                conn, addr = s.accept()
                tmp = conn.recv(1)
                if tmp == b'1':
                    print("Acknowledgement received")        

    def parse_args(self):
        err = False

        devs = self.args_dict["settings"]["devices"]

        for dev in devs:
            if dev["id"] == "Di":
                self.dev = dev
                self.cti_file = dev["plaintext_file"] + ".cpabe"
                self.pti_file = dev["plaintext_file"]
                self.num_req = int(dev["num_req"])
                self.abe_lib = dev["abe_lib"]

            if dev["id"] == "Dj":
                self.peer_ip = dev["host_ip"]
                self.peer_port = dev["port_data"]
                self.peer_dir = dev["workdir"]

            if dev["id"] == "SAi":
                self.edge_ip = dev["host_ip"]
                self.edge_port = dev["port_offload"]

            if dev["id"] == "SAj":
                self.peer_edge_ip = dev["host_ip"]
                self.peer_edge_dir = dev["workdir"]

    def get_cmds(self):
        if self.abe_lib == "cpabe":            
            self.cmd_setup = 'cpabe-setup'
            self.cmd_keygen_a = 'cpabe-keygen -o a_priv_key pub_key master_key temperature humidity'
            self.cmd_keygen_b = 'cpabe-keygen -o b_priv_key pub_key master_key pressure humidity'
            self.cmd_enc = "cpabe-enc pub_key " + self.pti_file + " 'temperature and humidity'"            
            self.send_keys_peer = "sshpass -p " + self.dev["scp_pwd"] + " scp pub_key a_priv_key sunanda@" + self.peer_ip + ":" + self.peer_dir
        else:
            self.cmd_setup = 'oabe_setup -s CP'
            self.cmd_keygen_a = 'oabe_keygen -s CP -i "temperature|humidity" -o a_priv'
            self.cmd_keygen_b = 'oabe_keygen -s CP -i "pressure|humidity" -o b_priv'
            self.cmd_enc = 'oabe_enc -s CP -e "temperature and humidity" -i ' + self.pti_file + ' -o ' + self.cti_file            
            self.send_keys_peer = "sshpass -p " + self.dev["scp_pwd"] + " scp mpk.cpabe a_priv.key sunanda@" + self.peer_ip + ":" + self.peer_dir


def main():
    pro = Provider(sys.argv[1])
    pro.parse_args()
    pro.get_cmds()
    pro.accept_data_request()
    pro.process_data_request()
    pro.send_processed_data()
    # ACK working for 1 data request only
    # if pro.ready == True:
    #     pro.receive_acknowledgement()
           

if __name__ == '__main__':
    main()
