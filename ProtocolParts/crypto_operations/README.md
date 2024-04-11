# Edge-based crypto offloading

This directory contains files to execute ABE and AES algorithms whose workings are briefly described below:

    1. client.py
        Encryption - The plaintext is sent to server.py and the ciphertext is received from it.
        Decryption - The keys are set up on the host device and the plaintext is encrypted using these keys. Next, The generated ciphertext and private keys are sent to server.py and the plaintext is received from it.

    2. server.py
        Encryption - The keys are set up on the host device and received plaintext is encrypted using these keys. After sending this ciphertext to client.py, it is decrypted in-place and compared against stored plaintext for verification.
        Decryption - The received ciphertext is decrypted using the received private keys and sent to client.py. The plaintext is compared against stored plaintext for verification.

    3. symmetric.py
        This file is used to execute encryption and decryption functions of AES algorithm for a key of size 32 bytes.


The respective plaintext and ciphertext sizes in bytes for all three crypto algorithms are listed below:

    Plaintext | CPABE OPENABE AES

    32        | 897   882     88

    512       | 1377  1522    728

    1024      | 1889  2206    1408

    2048      | 2913  3570    2776

