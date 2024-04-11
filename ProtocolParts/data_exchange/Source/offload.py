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

config_vals = dict()
durs = []
NUM_ROUNDS = 10
FILE_CLIENT = 'client-file'
PT = FILE_CLIENT + '.txt'
CT = PT + '.cpabe' 
HOST = '192.168.1.202'
PORT = 37021
SIZE_BUFF = 1024

def parse_args(args_list):
    err = False

    if args_list[1] == '--server' or args_list[1] == '1':
        config_vals['is_server'] = 1
    elif args_list[1] == '--client' or args_list[1] == '0':
        config_vals['is_server'] = 0
    else:
        print('Error passing host_device')
        err = True

    if args_list[2] == '--offload' or args_list[2] == '1':
        config_vals['do_offload'] = 1
    elif args_list[2] == '--no-offload' or args_list[2] == '0':
        config_vals['do_offload'] = 0
    else:
        print('Error passing energy_saving')
        err = True

    if args_list[3] == '--sgx' or args_list[3] == '1':
        config_vals['do_tee'] = 1
    elif args_list[3] == '--no-sgx' or args_list[3] == '0':
        config_vals['do_tee'] = 0
    else:
        print('Error passing trusted_execution')
        err = True

    if args_list[4] == '--abe' or args_list[4] == '1':
        config_vals['is_enc'] = 1
    elif args_list[4] == '--abd' or args_list[4] == '0':
        config_vals['is_enc'] = 0
    else:
        print('Error passing crypto_operation')
        err = True

    if args_list[5] == '--cpabe' or args_list[5] == '1':
        config_vals['cp_abe'] = 1
    elif args_list[5] == '--openabe' or args_list[5] == '0':
        config_vals['cp_abe'] = 0
    else:
        print('Error passing crypto_library')
        err = True

    if args_list[6] == '32' or args_list[6] == '512' or\
        args_list[6] == '1024' or args_list[6] == '2048':        
        config_vals['pt_b'] = args_list[6]
    else:
        print('Plaintext size not supported')
        err = True

    if err == True:
        help()      

def display_configuration(config_vals):
    print('***********************************************************************')
    print('CONFIGURATION PARAMETERS:\n')
    
    if config_vals['is_server'] == 1:
        print("Host device - EDGE (Desktop with Intel CPU)")
    else:
        print("Host device - END (Raspberry Pi Zero W)")

    if config_vals['do_offload'] == 1:
        print("Energy saving - Offload")
    else:
        print("Energy saving - No offload")  

    if config_vals['do_tee'] == 1:
        print("Trusted execution - Enabled (SGX)")
    else:
        print("Trusted execution - Disabled (SGX)") 

    if config_vals['is_enc'] == 1:
        print("Crypto operation - Attribute-based encryption")
    else:
        print("Crypto operation - Attribute-based decryption")    

    if config_vals['cp_abe'] == 1:
        print("Crypto library - CPABE")
    else:
        print("Crypto library - OpenABE")  

    print("Plaintext size (B) - {}\n".format(config_vals['pt_b']))

    print('***********************************************************************')

def help():
    print('Usage: python3 run.py host_device energy_saving trusted_execution crypto_operation crypto_library')
    print('Allowed values:')
    print('1. host_device: --server(1), --client(0)')
    print('2. energy_saving: --offload(1), --no-offload(0)')
    print('3. trusted execution: --sgx(1), --no-sgx(0)')
    print('4. crypto operation: --abe(1), --abd(0)')
    print('5. crypto library: --cpabe(1), --openabe(0)')
    print('6. plaintext size (B): 32, 512, 1024, 2048\n')

def main():
    parse_args(sys.argv)
    display_configuration(config_vals)

    is_server = config_vals['is_server']       
              
    if len(sys.argv) < 5:
        help()
        exit()

    do_offload = config_vals['do_offload'] 
    
    do_tee = config_vals['do_tee']

    is_enc = config_vals['is_enc']

    cp_abe = config_vals['cp_abe']

    pt_b = config_vals['pt_b']
    
    pt = 'pt' + config_vals['pt_b'] + '.txt' 

    if cp_abe == 1:            
        cmd_setup = 'cpabe-setup'
        cmd_keygen_i = 'cpabe-keygen -o sai_priv_key pub_key master_key temperature humidity'
        cmd_keygen_j = 'cpabe-keygen -o saj_priv_key pub_key master_key pressure humidity'
        cmd_enc = "cpabe-enc pub_key " + PT + " 'temperature and humidity'"
        cmd_dec_j = 'cpabe-dec pub_key saj_priv_key ' + CT # fails
        cmd_dec_i = 'cpabe-dec pub_key sai_priv_key ' + CT
    else:
        cmd_setup = 'oabe_setup -s CP'
        cmd_keygen_i = 'oabe_keygen -s CP -i "temperature|humidity" -o sai_priv'
        cmd_keygen_j = 'oabe_keygen -s CP -i "pressure|humidity" -o saj_priv'
        cmd_enc = 'oabe_enc -s CP -e "temperature and humidity" -i ' + PT + ' -o ' + CT
        cmd_dec_j = 'oabe_dec -s CP -k saj_priv.key -i ' + CT + ' -o ' + PT # fails
        cmd_dec_i = 'oabe_dec -s CP -k sai_priv.key -i ' + CT + ' -o ' + PT

    print('FEATURE IMPLEMENTATION:\n')
    if is_enc == 1:        
        if do_offload == 0:
            print("Start of setting up keys")     
            subprocess.run(cmd_setup, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(cmd_keygen_i, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("End of setting up keys\n")
            
            print("Number of iterations = {}\n".format(NUM_ROUNDS))
            for i in range(NUM_ROUNDS):  
                shutil.copyfile(pt, PT)
                if i == 0:
                    print("Start time for all encryptions = ",time.asctime())
                start = time.time()
                subprocess.run(cmd_enc, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                end = time.time()
                # Uncomment lines 82 till 84 for ciphertext length profiling
                # with open(CT, 'rb') as f:           
                #     line = f.read()
                #     print(len(line))                
                if i == NUM_ROUNDS - 1:
                    print("End time for all encryptions = ",time.asctime())
                durs.append(end - start)
                ctnew = CT + '.' + str(i)
                os.rename(CT, ctnew)
            print("Average duration (microseconds) = {}\n".format(1000000 * geometric_mean(durs)))

            print("Start of encryption check")
            err = False
            for i in range(NUM_ROUNDS):
                ctnew = CT + '.' + str(i)
                os.rename(ctnew, CT)
                subprocess.run(cmd_dec_i, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if filecmp.cmp(PT, pt, shallow=False) == False:
                    print('decryption error in round', i)
                    err = True
            if not err:
                print("Decryption of all ciphertexts matches with plaintext")
            print("End of encryption check\n")

        else:
            if is_server == 1:
                if do_tee == 1:
                    srv = Server(is_enc = True, do_tee = True, cp_abe = cp_abe, pt_b = pt_b)
                else:
                    srv = Server(is_enc = True, do_tee = False, cp_abe = cp_abe, pt_b = pt_b)
                srv.create()
                srv.run() 
            else:
                if do_tee == 1:          
                    clt = Client(is_enc = True, do_tee = True, cp_abe = cp_abe, pt_b = pt_b)
                else:
                    clt = Client(is_enc = True, do_tee = False, cp_abe = cp_abe, pt_b = pt_b)
                clt.create()
                clt.run()
    else:
        if do_offload == 0:
            print("Start of setting up keys") 
            subprocess.run(cmd_setup, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(cmd_keygen_i, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print("End of setting up keys")
            print("Number of iterations = ", NUM_ROUNDS)
            for i in range(NUM_ROUNDS):  
                shutil.copyfile(pt, PT)
                subprocess.run(cmd_enc, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                ctnew = CT + '.' + str(i)
                os.rename(CT, ctnew)

            for i in range(NUM_ROUNDS):
                ctnew = CT + '.' + str(i)
                os.rename(ctnew, CT)
                if i == 0:
                    print("Start time for all decryptions = ",time.asctime())
                start = time.time()
                subprocess.run(cmd_dec_i, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                end = time.time()
                if i == NUM_ROUNDS - 1:
                    print("End time for all decryptions = ",time.asctime())
                durs.append(end - start)
                if filecmp.cmp(PT, pt, shallow=False) == False:
                    print('decryption error in round', i) 
            print("Average duration (microseconds) = ", 1000000 * geometric_mean(durs))                       
        else:
            if is_server == 1:
                if do_tee == 1:
                    srv = Server(is_enc = False, do_tee = True, cp_abe = cp_abe, pt_b = pt_b)
                else:
                    srv = Server(is_enc = False, do_tee = False, cp_abe = cp_abe, pt_b = pt_b)
                srv.create()
                srv.run() 
            else:         
                if do_tee == 1:          
                    clt = Client(is_enc = False, do_tee = True, cp_abe = cp_abe, pt_b = pt_b)
                else:
                    clt = Client(is_enc = False, do_tee = False, cp_abe = cp_abe, pt_b = pt_b)
                clt.create()
                clt.run()
    print('***********************************************************************')
            

if __name__ == '__main__':
    main()
