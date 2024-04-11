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
from statistics import geometric_mean

class Requester:

    def __init__(self, args_file):
        # print("\n********END DEVICE: Dj********")
        with open(args_file) as f:
            self.args_dict = json.load(f)
            self.size_buff = 1024

    def send_data_request(self):        
        print("\nNumber of data requests - ", self.num_req)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.connect((self.peer_ip, int(self.peer_port)))            
            for i in range(self.num_req):
                if i == 0:
                    print("START: Sending request {} for data to Di - {}".format(i + 1, time.asctime()))
                    self.start_req = time.time()
                    if self.dev["do_opt"] == '1':
                        print(time.time())
                        
                conn.sendall(b'1')  
                # if i == self.num_req - 1:
                #     print("END: Sending request {} for data to Di".format(i + 1))
        self.ready_for_ack = False                                                      

    def process_received_data(self):
        if self.dev["do_offloading"] == '0': 
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind((self.dev["host_ip"], int(self.dev["port_data"])))
                s.listen()
                conn = None
                while not conn:
                    # print("\n~~~Waiting to receive requested data from Di~~~")
                    conn, addr = s.accept() 
                    # msg_w = ''  
                    for i in range(self.num_req):
                        # if i == 0:
                        #     print("START: Receive ABD input {} from Di", i + 1)
                        msg = conn.recv(int(self.dev["abe_ciphertext_size"]))                    
                        if i == self.num_req - 1:
                            print("END: Receive ABD input {} from Di - {}".format(i + 1, time.asctime()))
                            self.end_req = time.time()                 
                    with open(self.ctj_file, 'wb') as f: 
                        f.write(msg) 
                    req_time = (self.end_req - self.start_req) / self.num_req
                    print("Mean data request time - {} microseconds".format(req_time * 1000000))                                                          
            
            shutil.copyfile(self.ctj_file, self.ctj_file + ".bak")
            print("\nNumber of ABDs - ", self.num_abd)
            copy_times = []
            abd_times = []
            for i in range(self.num_abd):
                if i == 0:
                    print("START: Decrypt received data {} using ABD - {}".format(i + 1, time.asctime()))
                start_abd = time.time()
                subprocess.run(self.cmd_dec_a, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                end_abd = time.time()
                if i == self.num_abd - 1:
                    print("END: Decrypt received data {} using ABD - {}".format(i + 1, time.asctime()))
                start = time.time()
                shutil.copyfile(self.ctj_file + ".bak", self.ctj_file)
                end = time.time()
                abd_times.append(end_abd - start_abd)
                copy_times.append(end - start)
            print("Mean ABD time - {} microseconds".format(geometric_mean(abd_times) * 1000000))
            print("Mean copy time - {} microseconds".format(geometric_mean(copy_times) * 1000000))

            with open(self.ptj_file, 'r') as f:
                print("result = ",f.read())
            self.ready_for_ack = True
        else:
            if self.dev["do_opt"] == '0':
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind((self.dev["host_ip"], int(self.dev["port_data"])))
                    s.listen()
                    conn = None
                    self.aes_abe_ct = ''
                    while not conn:
                        # print("\n~~~Waiting to receive encrypted ABE output from Di~~~")
                        conn, addr = s.accept()
                        for i in range(self.num_req):
                            # if i == 0:
                            #     print("START: Receive ABD input {} from Di".format(i + 1))
                            line = conn.recv(int(self.dev["aes_abe_ciphertext_size"]))                  
                            if not self.aes_abe_ct:
                                self.aes_abe_ct = line
                            if i == self.num_req - 1:
                                print("END: Receive ABD input {} from Di - {}".format(i + 1, time.asctime()))
                            self.end_req = time.time()
                req_time = (self.end_req - self.start_req) / self.num_req
                print("Mean data request time - {} microseconds".format(req_time * 1000000))
                
                print("\nNumber of AES\' - ", self.num_aes)
                aes_dec_times = []                       
                for i in range(self.num_aes):
                    if i == 0:
                        print("START: Decrypt received data using AES - ", time.asctime())
                    with open(self.dev["aes_key_file"]) as f:
                        self.aes_key = f.read()
                    start = time.time()            
                    obj = AESCipher(self.aes_key, int(self.dev["aes_key_size"]))
                    self.abe_ct = unpad(obj.decryptCBCbytes(self.aes_abe_ct), obj.block_size)
                    end = time.time()
                    if i == self.num_aes - 1:
                        print("END: Decrypt received data using AES - ", time.asctime())
                    aes_dec_times.append(end - start)
                print("Mean AES decryption time - {} microseconds".format(geometric_mean(aes_dec_times) * 1000000))

                print("\nNumber of ABDs - ", self.num_abd)
                abd_off_times = []  
                self.aes_ct = ''
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
                    conn.connect((self.edge_ip, int(self.edge_port)))
                    for i in range(self.num_abd):
                        if i == 0:
                            print("START: Send ABD input to and receive ABD output {} from SAj - {}".format(i + 1, time.asctime()))
                        start = time.time()
                        conn.sendall(self.abe_ct)
                        line = conn.recv(int(self.dev["aes_ciphertext_size"]))                  
                        if not self.aes_ct:
                            self.aes_ct = line
                        end = time.time()
                        if i == self.num_abd - 1:
                            print("END: Send ABD input to and receive ABD output {} from SAj - {}".format(i + 1, time.asctime()))
                        abd_off_times.append(end - start)
                print("Mean offloaded ABD time - {} microseconds".format(geometric_mean(abd_off_times) * 1000000))
            else:
                print("\nNumber of ABDs - ", self.num_abd)                  
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind((self.dev["host_ip"], int(self.dev["port_offload"])))
                    s.listen()
                    conn = None
                    while not conn:
                        conn, addr = s.accept()  
                        abd_off_times = []
                        for i in range(self.num_abd):
                            # if i == 0:
                            #     print("START: Receive encrypted ABD output from SAj - ", time.asctime())
                            start = time.time()

                            self.aes_ct = conn.recv(int(self.dev["aes_ciphertext_size"]))   

                            end = time.time()
                            if i == self.num_abd - 1:
                                print("END: Receive encrypted ABD output from SAj - ", time.asctime())
                                print(time.time())            

            print("\nNumber of AES\' - ", self.num_aes)
            aes_dec_times = []  
            self.aes_pt = ''                     
            for i in range(self.num_aes):
                if i == 0:
                    print("\nSTART: Retrieve requested data on Dj - ", time.asctime())
                with open(self.dev["aes_key_file"]) as f:
                    self.aes_key = f.read()
                start = time.time()
                obj = AESCipher(self.aes_key, int(self.dev["aes_key_size"]))
                pt = obj.decryptCBC(self.aes_ct)
                end = time.time()
                if not self.aes_pt:
                    self.aes_pt = pt
                if i == self.num_aes - 1:
                    print("END: Retrieve requested data on Dj - {}, result = {}".format(time.asctime(), self.aes_pt))
                aes_dec_times.append(end - start)
            print("Mean AES decryption time - {} microseconds".format(geometric_mean(aes_dec_times) * 1000000))

    def finish_data_request(self):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
            conn.connect((self.peer_ip, int(self.peer_port)))
            print("\nSTART: Sending acknowledgement to Di")
            conn.sendall(b'1')  
            print("END: Sending acknowledgement to Di")

    def parse_args(self):
        err = False

        devs = self.args_dict["settings"]["devices"]

        for dev in devs:
            if dev["id"] == "Dj":
                self.dev = dev
                self.ctj_file = dev["plaintext_file"] + ".cpabe"
                self.ptj_file = dev["plaintext_file"]
                self.num_req = int(dev["num_req"])
                self.num_abd = int(dev["num_abd"])
                self.num_aes = int(dev["num_aes"])
                self.abe_lib = dev["abe_lib"]

            if dev["id"] == "Di":
                self.peer_ip = dev["host_ip"]
                self.peer_port = dev["port_data"]

            if dev["id"] == "SAj":
                self.edge_ip = dev["host_ip"]
                self.edge_port = dev["port_offload"]
                
    def get_cmds(self):
        if self.abe_lib == "cpabe":                 
            self.cmd_dec_a = 'cpabe-dec pub_key a_priv_key ' + self.ctj_file
        else:   
            self.cmd_dec_a = 'oabe_dec -s CP -k a_priv.key -i ' + self.ctj_file + " -o " + self.ptj_file


def main():
    req = Requester(sys.argv[1])
    req.parse_args()
    req.get_cmds()
    req.send_data_request()
    req.process_received_data()
    # ACK working for 1 data request only
    # if req.ready_for_ack == True:
    #     req.finish_data_request()


if __name__ == '__main__':
    main()
