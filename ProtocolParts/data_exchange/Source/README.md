# Execution Steps

This directory contains all files required to execute the data exchange protocol. The plaintexts used for all experiments are placed inside input folder. The instructions to execute these files are mentioned below.

Step 1

    offload.py
        Performs no-offloading or offloading of ABE operations. 
        During offloading of ABE, plaintext is excrypted with AES before sending to edge device. 
        During offloading of ABD, plaintext generated on edge device is encrypted with AES before sending to end device. 
        Currently, the AES symmetric key of size 256 bits is stored in advance on both end and edge device.

    Usage: python3 offload.py host_device energy_saving trusted_execution crypto_operation crypto_library

    Parameter values:
        1. host_device          : --server(1), --client(0)
        2. energy_saving        : --offload(1), --no-offload(0)
        3. trusted execution    : --sgx(1), --no-sgx(0)
        4. crypto operation     : --abe(1), --abd(0)
        5. crypto library       : --cpabe(1), --openabe(0)


Step 2

    Usage:
        Di      - python3 provider.py args.txt
        Dj      - python3 requester.py args.txt
        SAi&j   - python3 edge.py args.txt

    The file args.txt contains dictionary fields for following attributes of each device:
        id                          - Device name 
        host_ip                     - IPv4 address of the host device
        port_data                   - Network port to send/receive data during secure data exchange 
        port_offload                - Network port to send/receive data during offloading of ABE/ABD
        do_offloading               - Perform crypto offloading
        do_tee                      - Offload to SGX enclave
        do_opt                      - Use enhanced protocol
        abe_lib                     - ABE crypto library name
        plaintext_size              - Size of plaintext in bytes
        plaintext_file              - Location of plaintext
        abe_ciphertext_size         - Size of corresponding ciphertext in bytes
        aes_key_file                - Location of AES key 
        aes_key_size                - Size of AES key in bytes
        aes_ciphertext_size         - Size of AES encrypted plaintext in bytes
        aes_abe_ciphertext_size     - Size of AES encrypted ABE ciphertext in bytes (TODO: remove this layer)
        workdir                     - Absolute path of current directory 
        num_req                     - Number of data requests
        num_abd                     - Number of ABDs
        num_aes                     - Number of AES decryptions
        scp_pwd                     - Network password of recipient device 


    Steps for installing SGX binaries of ABE commands

        CPABE

        1. cpabe-setup
            cp Makefile.csetup Makefile
            cp manifest.template.csetup manifest.template
            make SGX=1

        2. cpabe-keygen
            cp Makefile.ckeygen_i Makefile
            cp manifest.template.ckeygen_i manifest.template (Replace i with j for appropriate domain)
            make SGX=1

        3. cpabe-enc
            cp Makefile.cenc Makefile
            cp manifest.template.cenc manifest.template
            make SGX=1

        4. cpabe-dec
            cp Makefile.cdec Makefile
            cp manifest.template.cdec manifest.template
            make SGX=1 

        
        OPENABE

        1. oabe_setup
            cp Makefile.osetup Makefile
            cp manifest.template.osetup manifest.template
            make SGX=1

        2. oabe_keygen
            cp Makefile.okeygen_i Makefile
            cp manifest.template.okeygen_i manifest.template (Replace i with j for appropriate domain)
            make SGX=1

        3. oabe_enc
            cp Makefile.oenc Makefile
            cp manifest.template.oenc manifest.template
            make SGX=1

        4. oabe_dec
            cp Makefile.odec Makefile
            cp manifest.template.odec manifest.template
            make SGX=1
