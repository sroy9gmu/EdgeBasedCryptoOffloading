# Setting up the environment

This page lists detailed instructions for installing necessary packages which are required for executing the reference as well as enhanced protocol.

1.  AES crypto library - Please follow instructions at https://github.com/sroy9gmu/MicroprocessorBasedCryptoCharacterization/tree/main/CryptoLibraries/PyCryptodome 

2.  ABE crypto libraries

        2.1 CPABE

            Links:

                1. https://acsc.cs.utexas.edu/cpabe/ 

                2. https://stackoverflow.com/questions/17373306/error-in-linking-gmp-while-compiling-cpabe-package-from-its-source-code 

            Dependent Packages:

                cpabe-0.11

                gmp-6.2.1 (sudo apt-get install lzip. Download and install package separately on end and edge device)

                libbswabe-0.9

                pbc-0.5.14 (sudo apt-get install flex bison)

                glib-2.0 (sudo apt-get install libglib2.0-dev)

            Compilation:

                1. ./configure -with-pbc-include=/usr/local/include/pbc -with-pbc-lib=/usr/local/lib
                
                2. x86_64 -> make LDFLAGS="-lgmp -lpbc -lcrypto -L/usr/lib/x86_64-linux-gnu -lglib-2.0 -lbswabe -lgmp"
                Pi Zero W -> make LDFLAGS="-lgmp -lpbc -lcrypto -L/usr/lib/arm-linux-gnueabihf -lglib-2.0 -lbswabe -lgmp"

                3. Edit policy_lang.y:67:38: error: expected ‘;’ before ‘}’ token
                    In function ‘yyparse’:
                    OLD -> result: policy { final_policy = $1 }
                    NEW -> result: policy { final_policy = $1; }

                4. sudo make install

            Commands:

                1. cpabe-setup

                2. cpabe-keygen -o sai_priv_key pub_key master_key temperature humidity

                3. cpabe-keygen -o saj_priv_key pub_key master_key pressure humidity

                4. cpabe-enc pub_key client-file.txt 'temperature and humidity'

                5. cpabe-dec pub_key saj_priv_key client-file.txt.cpabe -> fails


        2.2 OpenABE

            Repos:

                1. x86_64 -> https://github.com/zeutro/openabe

                2. Pi Zero W -> https://github.com/PekeDevil/openabe 

            Issues: 

                1. https://github.com/zeutro/openabe/issues/61 

                2. https://github.com/zeutro/openabe/issues/62

            Compilation:

                1. If build stops, do ‘sudo ldconfig’ and rebuild without clean

                2. If facing gtest related errors:
                    2.1 Remove ‘gtest’ from Makefile.common line 45
                    2.2 Go to deps/gtest/ and run ‘./download_gtest.sh 1.8.0’
                    2.3 cd google_test…./
                    2.4 mkdir mybuild
                    2.5 cd mybuild
                    2.6 cmake -G"Unix Makefiles" ..
                    2.7 make
                    2.8 sudo -E make install

                3. If facing openssl related errors:
                    3.1 Remove ‘openssl’ from Makefile.common line 45
                    3.2 make
                    3.3 sudo -E make install

                4. If facing bison related errors: export BISON=bison

                5. After OPENABE installation,
                    sudo cp /usr/local/lib/libcrypto.so.1.1 /usr/local/lib/libcrypto.so.1.1.oabe
                    sudo cp /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 /usr/local/lib/libcrypto.so.1.1

            Commands:

                1. oabe_setup -s CP

                2. oabe_keygen -s CP -i "temperature|humidity" -o sai_priv

                3. oabe_enc -s CP -e "temperature and humidity" -i client-file.txt -o client-file.txt.cpabe

                4. oabe_dec -s CP -k sai_priv.key -i client-file.txt.cpabe -o client-file.txt

3.  Trusted Execution Environment (Intel SGX)

        3.1 SGX Driver

            1. To enable SGX on your machine, first enable SGX driver in BIOS settings if not enabled by default. 
                Refer: https://github.com/intel/sgx-software-enable 

            2. Fix curl related errors: 
                https://stackoverflow.com/questions/34914944/could-not-find-curl-missing-curl-library-curl-include-dir-on-cmake 

            3. Check FLC support: 
                https://www.intel.com/content/www/us/en/support/articles/000057420/software/intel-security-products.html  
            
            4. Fix BTF errors: 
                https://askubuntu.com/questions/1348250/skipping-btf-generation-xxx-due-to-unavailability-of-vmlinux-on-ubuntu-21-04  
                sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/

            5. Verify below settings for executing in hardware debug mode
                $ is-sgx-available
                SGX supported by CPU: true
                SGX1 (ECREATE, EENTER, ...): true
                SGX2 (EAUG, EACCEPT, EMODPR, ...): false
                Flexible Launch Control (IA32_SGXPUBKEYHASH{0..3} MSRs): false
                SGX extensions for virtualizers (EINCVIRTCHILD, EDECVIRTCHILD, ESETCONTEXT): false
                Extensions for concurrent memory management (ETRACKC, ELDBC, ELDUC, ERDINFO): false
                CET enclave attributes support (See Table 37-5 in the SDM): false
                Key separation and sharing (KSS) support (CONFIGID, CONFIGSVN, ISVEXTPRODID, ISVFAMILYID report fields): false
                Max enclave size (32-bit): 0x80000000
                Max enclave size (64-bit): 0x1000000000
                EPC size: 0x5d80000
                SGX driver loaded: true
                AESMD installed: true
                SGX PSW/libsgx installed: true    

            6. If facing sgx driver errors, try following steps:
                6.1 Ensure sgx is enabled by reboot system and pressing F2.
                6.2 Build and install driver from github source:
                    https://github.com/intel/linux-sgx-driver
                6.3 Reboot and check /dev/isgx is installed.
                6.4 If still facing errors, install driver from x64 binary located in libraries folder and reboot
                    6.4.1 sudo cp /sys/kernel/btf/vmlinux /usr/lib/modules/`uname -r`/build/
                    6.4.2 sudo ./sgx_linux_x64_driver_2.11.54c9c4c.bin
                    6.4.3 sudo /sbin/depmod
                    6.4.4 sudo /sbin/modprobe isgx
                    6.4.5 sudo reboot

            7. Reference document:
                https://download.01.org/intel-sgx/latest/linux-latest/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf

            8. If facing open PGP errors, refer: 
                https://stackoverflow.com/questions/21338721/gpg-no-valid-openpgp-data-found 


        3.2 Gramine Driver and Software

            1. Install and verify Gramine-SGX interface on target machine using: 
                https://gramine.readthedocs.io/en/latest/quickstart.html
            
            2. Follow instructions at https://gramine.readthedocs.io/en/stable/devel/building.html to install driver, PSW and SDK in order. 
                Install oot driver since no FLC support and \dev\sgx_enclave is missing. 
                Refer https://gitter.im/gramineproject/community in case of errors
                sudo apt-get install gramine-oot 

            3. sudo apt-get -y install nasm

            4. git clone https://github.com/gramineproject/gramine.git

            5. cd gramine

            6. sudo apt-get install protobuf-c-compiler protobuf-compiler pkg-config libcurl4-openssl-dev libprotobuf-c-dev

            7. meson setup build/ --buildtype=release -Ddirect=enabled -Dsgx=enabled -Dsgx_driver=oot \
                -Dsgx_driver_include_path=<path to linux-sgx-driver source repo>

            8. ninja -C build/   

            9. sudo ninja -C build/ install

            10. Obtain SPID from https://api.portal.trustedservices.intel.com/EPID-attestation

            11. If facing AESMD errors, follow instructions to restart service at 
                https://github.com/intel/linux-sgx


