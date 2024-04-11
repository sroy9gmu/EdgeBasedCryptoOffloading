# Authenticating edge device with end device (one-time)

Preparation:

    1. Register edge device to obtain SPID and keys - https://api.portal.trustedservices.intel.com/EPID-attestation

    2. Baseline software - https://github.com/gramineproject/gramine/tree/master/CI-Examples/ra-tls-mbedtls

    3. Intel Attestation Services - https://www.intel.com/content/www/us/en/developer/tools/software-guard-extensions/attestation-services.html

    4. Mid-level RA-TLS interface - https://gramine.readthedocs.io/en/stable/attestation.html


Setup edge device (server):

    1. Clone Gramine repo and install dependencies as required:
        https://github.com/gramineproject/gramine/tree/master

    2. Verify SGX driver (/dev/isgx) is up and running.

    3. Execute below commands inside gramine/CI-Examples/ra-tls-mbedtls/:

        3.1 make clean
        3.2 make app epid RA_TYPE=epid RA_CLIENT_SPID=<SPID from IAS> RA_CLIENT_LINKABLE=0
        3.3 sudo gramine-sgx ./server
            This command starts the Gramine server process. Note the values of mr_enclave and mr_signer in the output.


Setup end device (client):

    1. Clone Gramine repo only:
        https://github.com/gramineproject/gramine/tree/master

    2. To install dependent packages required for executing Gramine's client process, follow below steps:

        2.1 Install the respective versions of libraries listed inside gramine/subprojects
        2.2 For compiling MBEDTLS shared libraries, run below command before running make:
             export SHARED=1
        2.3 Install CURL using below commands:
            2.3.1 git clone https://github.com/curl/curl.git
            2.3.2 autoreconf -fi
            2.3.3 ./configure --with-mbedtls
            2.3.4 make
            2.3.5 sudo make install

    3. Compile RA-TLS source files:

        3.1 cd gramine/tools/sgx/common. Edit ias.c as shown below:
             # include <cjson/cJSON.h>
        3.2 Edit util.c, remove the noreturn word towards the end of file
                'noreturn' void abort(void) {
                    _Exit(ENOTRECOVERABLE);
                }
        3.3 cd gramine/tools/sgx/ra-tls. In ra_tls.h, add <stddef.h> header file. Compile ra_tls_verify_epid.c:
             gcc -c -fPIC -nostartfiles -I/usr/local/musl/include -I/usr/local/include -I<parent dir>/gramine/tools/sgx/common -I<parent dir>/gramine/pal/src/host/linux-sgx ra_tls_verify_epid.c ra_tls_verify_common.c <parent dir>/gramine/tools/sgx/common/util.c <parent dir>/gramine/tools/sgx/common/ias.c <parent dir>/gramine/tools/sgx/common/quote.c ra_tls.h -lmbedtls -lmbedx509 -lmbedcrypto -lcurl -lcjson
        3.4 Create shared library ra_tls_verify_epid.so:
             gcc -shared -fPIC -Wl,-soname,libra_tls_verify_epid.so.1 -o libra_tls_verify_epid.so.1.1.0 ias.o quote.o ra_tls_verify_common.o ra_tls_verify_epid.o util.o -lc
        3.5 Create soft links to shared libraries after installing ra_tls_verify_epid.so inside /usr/local/lib:
                ln -s libra_tls_verify_epid.so.1.1.0 libra_tls_verify_epid.so.1
                ln -s libra_tls_verify_epid.so.1.1.0 libra_tls_verify_epid.so

    4. Start the Gramine client process as shown below:

        4.1 cd gramine/CI-Examples/ra-tls-mbedtls/src
        4.2 Copy ../ssl directory contents from server to client.
        4.3 Edit server name and location of ca.crt in client.c and compile:
             gcc -I<parent dir>/gramine/tools/sgx/ra-tls -I/usr/local/include client.c -lra_tls_verify_epid -lcjson -lcurl -ldl -lmbedtls -lmbedx509 -lmbedcrypto -lm -o client
        4.4 Verify Gramine server's enclave credentials from IAS:
             RA_TLS_ALLOW_DEBUG_ENCLAVE_INSECURE=1 RA_TLS_ALLOW_OUTDATED_TCB_INSECURE=1 RA_TLS_EPID_API_KEY=<Primary key>  RA_TLS_MRENCLAVE=<mr_enclave> RA_TLS_MRSIGNER=<mr_signer> RA_TLS_ISV_PROD_ID=0  RA_TLS_ISV_SVN=0 ./client epid