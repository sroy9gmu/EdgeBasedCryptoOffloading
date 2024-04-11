from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import BLAKE2b
from base64 import b64decode
from base64 import b64encode
import time
import sys
import os
import shutil
import pickle
from statistics import geometric_mean

num_cmd_iter = 1
algorithms = ["AES"]
modes = ["CBC"]#["ECB", "CBC", "CFB", "OFB", "CTR"]
hashed_key_lengths = [32]#[16, 24, 32]

#AES-ECB specific start____________________________________________________________
#https://gist.github.com/h0rn3t/4216cf787b43060b5afc2d50086918bc

# Padding for the input string --not
# related to encryption itself.
BLOCK_SIZE = 16  # Bytes
padECB = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * \
                chr(BLOCK_SIZE - len(s) % BLOCK_SIZE)
unpadECB = lambda s: s[:-ord(s[len(s) - 1:])]

#AES-ECB specific end______________________________________________________________

#AES-CBC specific start____________________________________________________________
#https://gist.github.com/lopes/168c9d74b988391e702aac5f4aa69e41
  
#AES-CBC specific end______________________________________________________________

#AES-(CFB, OFB, CTR) specific start________________________________________________
#https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html

#AES-(CFB, OFB, CTR) specific end__________________________________________________

class AESCipher:
    """
    Usage:
        c = AESCipher('password').encrypt('message')
        m = AESCipher('password').decrypt(c)
    Tested under Python 3 and PyCrypto 2.6.1.
    """

    def __init__(self, pwd, key_length):
        pwd_b = str.encode(pwd)
        h = BLAKE2b.new(digest_bytes=key_length, key=pwd_b)
        self.key = h.digest()
        self.block_size = AES.block_size

    def encryptECB(self, raw):
        raw = padECB(raw)
        cipher = AES.new(self.key, AES.MODE_ECB)
        ct = cipher.encrypt(raw.encode('utf8'))
        return b64encode(ct)

    def decryptECB(self, data):
        data = b64decode(data)
        cipher = AES.new(self.key, AES.MODE_ECB)
        dt = cipher.decrypt(data)
        return unpadECB(dt).decode('utf8')

    # @profile   # Enable for memory usage
    def encryptCBC(self, data):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(pad(data.encode('utf-8'), AES.block_size))
        return b64encode(iv + ct)

    def encryptCBCbytes(self, data):
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(data)
        return iv + ct

    # @profile   # Enable for memory usage
    def decryptCBC(self, data):
        raw = b64decode(data)
        cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        dt = cipher.decrypt(raw[AES.block_size:])
        return unpad(dt, AES.block_size).decode('utf-8')

    def decryptCBCbytes(self, data):
        cipher = AES.new(self.key, AES.MODE_CBC, data[:AES.block_size])
        dt = cipher.decrypt(data[AES.block_size:])
        return dt

    def encryptXXX(self, data, mode): 
        if mode == "CFB":
            cipher = AES.new(self.key, AES.MODE_CFB)
        elif mode == "OFB":
            cipher = AES.new(self.key, AES.MODE_OFB)
        elif mode == "CTR":
            cipher = AES.new(self.key, AES.MODE_CTR)
        ct_bytes = cipher.encrypt(str.encode(data))
        ct = b64encode(ct_bytes)       
        
        if mode != "CTR":
            iv = b64encode(cipher.iv)
            return iv, ct    
        else:
            nonce = b64encode(cipher.nonce)
            return nonce, ct

    def decryptXXX(self, data, iv_or_nonce, mode):
        raw_iv_or_nonce = b64decode(iv_or_nonce)
        raw_data = b64decode(data)
        
        if mode == "CFB":
            cipher = AES.new(self.key, AES.MODE_CFB, iv=raw_iv_or_nonce)
        elif mode == "OFB":
            cipher = AES.new(self.key, AES.MODE_OFB, iv=raw_iv_or_nonce)
        elif mode == "CTR":
            cipher = AES.new(self.key, AES.MODE_CTR, nonce=raw_iv_or_nonce)

        dt = cipher.decrypt(raw_data).decode('utf-8')
        return dt

def main():  
    fp = open(sys.argv[1])
    msg = fp.read()
    fp.close()
        
    fp = open(sys.argv[2])
    pwd = fp.read()
    fp.close()    
        
    if sys.argv[4] != "AES":
        print("TBD")
        exit()
        
    results_dir = sys.argv[3]
    is_rerun = False
    
    # Disable lines 127 till 139 for detailed profiling of decryption
    if os.path.exists(results_dir):
        is_rerun = True
        shutil.rmtree(results_dir)
    access_rights = 0o755
    try:
        os.mkdir(results_dir, access_rights)
    except OSError:
        print ("Creation of the directory {} failed".format(results_dir))
    else:
        if is_rerun == False:
            print ("Successfully created the directory {}".format(results_dir))
        else:
            print ("Successfully re-created the directory {}".format(results_dir))

    fp_time = open(os.path.join(results_dir, "ProfilingTimes"), 'a')

    encops = os.path.join(results_dir, 'cts')
    ivops = os.path.join(results_dir, 'ivs')
    nonceops = os.path.join(results_dir, 'nonces')
               
    for mode in modes:
        for key_length in hashed_key_lengths:            
            curr_res_key = sys.argv[4] + '-' + str(key_length) + '-' + mode 
            fp_time.write("{}\n".format(curr_res_key))
            
            # Perform encryption for required number of times            
            enc_all_dur = []
            enc_all_ops = []
            iv_all_ops = []
            nonce_all_ops = []  
            enc_all_ops = []
            enc_all_lens = []
            fp_time.write("Encryption start time = {}.\n".format(time.asctime()))
            for it in range(num_cmd_iter):
                curr = AESCipher(pwd, key_length)
                enc_it_start = time.time()
                if mode == "ECB":
                    enc_all_ops.append(curr.encryptECB(msg))
                elif mode == "CBC":
                    enc_all_ops.append(curr.encryptCBC(msg))
                elif mode == "CFB" or mode == "OFB":                    
                    iv, ct = curr.encryptXXX(msg, mode)
                    iv_all_ops.append(iv)
                    enc_all_ops.append(ct) 
                elif mode == "CTR":
                    nonce, ct = curr.encryptXXX(msg, mode)                   
                    nonce_all_ops.append(nonce)
                    enc_all_ops.append(ct)
                enc_it_end = time.time()
                enc_all_dur.append(enc_it_end - enc_it_start)
                # Enable below line ciphertext length profiling
                enc_all_lens.append(len(enc_all_ops[it]))
            fp_time.write("Encryption end time = {}.\n".format(time.asctime()))
            enc_mean_dur = geometric_mean(enc_all_dur)
            # For detailed profiling only
            # fp_time.write("Detailed profiling enc start - {}\n".format(enc_it_start))
            # fp_time.write("Detailed profiling enc end - {}\n".format(enc_it_end))
            fp_time.write("Encryption mean duration for {} iterations = {} seconds.\n"\
                .format(num_cmd_iter, enc_mean_dur))
            with open(encops,'wb') as fp:
                pickle.dump(enc_all_ops, fp)
            with open(ivops,'wb') as fp:
                pickle.dump(iv_all_ops, fp)
            with open(nonceops,'wb') as fp:
                pickle.dump(nonce_all_ops, fp)
            # Enable lines 194 till 198 for ciphertext length profiling
            if enc_all_lens.count(enc_all_lens[0]) != len(enc_all_lens):
                fp_time.write("Ciphertext length varies across iterations.\n")
                fp_time.write("Maximum ciphertext length (bytes) = {}.\n".format(max(enc_all_lens)))
            else:
                fp_time.write("Ciphertext length (bytes) = {}.\n".format(enc_all_lens[0]))
            
            # Perform decryption for required number of times
            dec_all_dur = []
            dec_all_ops = []  
            with open(encops, 'rb') as fp:
                cts = pickle.load(fp)
            with open(ivops, 'rb') as fp:
                ivs = pickle.load(fp)
            with open(nonceops, 'rb') as fp:
                nonces = pickle.load(fp)
            fp_time.write("Decryption start time = {}.\n".format(time.asctime()))
            for it in range(num_cmd_iter):
                curr = AESCipher(pwd, key_length)
                dec_it_start = time.time()
                ct = cts[it]
                if mode == "ECB":
                    dec_all_ops.append(curr.decryptECB(ct))
                elif mode == "CBC":
                    dec_all_ops.append(curr.decryptCBC(ct))
                elif mode == "CFB" or mode == "OFB":                    
                    iv = ivs[it]
                    dec_all_ops.append(curr.decryptXXX(ct, iv, mode))
                elif mode == "CTR":
                    nonce = nonces[it]
                    dec_all_ops.append(curr.decryptXXX(ct, nonce, mode))
                dec_it_end = time.time()
                dec_all_dur.append(dec_it_end - dec_it_start)
            fp_time.write("Decryption end time = {}.\n".format(time.asctime()))
            dec_mean_dur = geometric_mean(dec_all_dur)
            # For profiling only
            # fp_time.write("Detailed profiling dec start - {}\n".format(dec_it_start))
            # fp_time.write("Detailed profiling dec end - {}\n".format(dec_it_end))
            fp_time.write("Decryption mean duration for {} iterations = {} seconds.\n"\
                .format(num_cmd_iter, dec_mean_dur))
            
            # Check for correctness of decrypted outputs       
            err_found = False
            for it in range(num_cmd_iter):
                if dec_all_ops[it] != msg:
                    fp_time.write("Decryption error occured in {} iteration.".format(it))
                    fp_time.write("Actual text: {}".format(dec_all_ops[it]))
                    fp_time.write("Original text: {}".format(msg))
                    if err_found == False:
                        err_found = True
            if err_found == False:
                fp_time.write("No decryption error occured.")
                   
    fp_time.close()
  
def show_help():
    print("Usage: python3 " + sys.argv[0] + " [file to be encrypted/decrypted]\
         [file containing password] [results foldername] [algorithm]")
    print("Values for \'algorithm\': (executes all if not specified)")
    print(', '.join(map(str, algorithms)))     
    print("NOTE: Only AES results have been verified")
    
if __name__=='__main__':
    main()
