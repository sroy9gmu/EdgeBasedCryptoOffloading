/* SPDX-License-Identifier: Apache-2.0 */
/* Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *               2020, Intel Labs
 */

/*
 * SSL client demonstration program (with RA-TLS).
 * This program is originally based on an mbedTLS example ssl_client1.c but uses RA-TLS flows (SGX
 * Remote Attestation flows) if RA-TLS library is required by user.
 * Note that this program builds against mbedTLS 3.x.
 */

#include "mbedtls/build_info.h"

#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <stdint.h>	/* for uint64 definition */
#include <stdlib.h>	/* for exit() definition */
#include <time.h>	/* for clock_gettime */
#include <unistd.h>
#include <math.h>

#define PROFILE
#define BILLION 1000000000L
#define NUM_ROUNDS 30

#define mbedtls_fprintf fprintf
#define mbedtls_printf printf

#define MBEDTLS_EXIT_SUCCESS EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE EXIT_FAILURE

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/debug.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"

#include "ra_tls.h"

/* RA-TLS: on client, only need to register ra_tls_verify_callback_extended_der() for cert
 * verification. */
int (*ra_tls_verify_callback_extended_der_f)(uint8_t* der_crt, size_t der_crt_size,
                                             struct ra_tls_verify_callback_results* results);

/* RA-TLS: if specified in command-line options, use our own callback to verify SGX measurements */
void (*ra_tls_set_measurement_callback_f)(int (*f_cb)(const char* mrenclave, const char* mrsigner,
                                          const char* isv_prod_id, const char* isv_svn));

#define SERVER_PORT "4433"
#define SERVER_NAME "192.168.1.202"
#define GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define DEBUG_LEVEL 0

#define CA_CRT_PATH "../ssl/ca.crt"

static double diff[NUM_ROUNDS];
struct timespec t1, t2;

static void my_debug(void* ctx, int level, const char* file, int line, const char* str) {
    ((void)level);

    mbedtls_fprintf((FILE*)ctx, "%s:%04d: %s\n", file, line, str);
    fflush((FILE*)ctx);
}

static int parse_hex(const char* hex, void* buffer, size_t buffer_size) {
    if (strlen(hex) != buffer_size * 2)
        return -1;

    for (size_t i = 0; i < buffer_size; i++) {
        if (!isxdigit(hex[i * 2]) || !isxdigit(hex[i * 2 + 1]))
            return -1;
        sscanf(hex + i * 2, "%02hhx", &((uint8_t*)buffer)[i]);
    }
    return 0;
}


/* expected SGX measurements in binary form */
static char g_expected_mrenclave[32];
static char g_expected_mrsigner[32];
static char g_expected_isv_prod_id[2];
static char g_expected_isv_svn[2];

static bool g_verify_mrenclave   = false;
static bool g_verify_mrsigner    = false;
static bool g_verify_isv_prod_id = false;
static bool g_verify_isv_svn     = false;

/* RA-TLS: our own callback to verify SGX measurements */
static int my_verify_measurements(const char* mrenclave, const char* mrsigner,
                                  const char* isv_prod_id, const char* isv_svn) {
    assert(mrenclave && mrsigner && isv_prod_id && isv_svn);

    if (g_verify_mrenclave &&
            memcmp(mrenclave, g_expected_mrenclave, sizeof(g_expected_mrenclave)))
        return -1;

    if (g_verify_mrsigner &&
            memcmp(mrsigner, g_expected_mrsigner, sizeof(g_expected_mrsigner)))
        return -1;

    if (g_verify_isv_prod_id &&
            memcmp(isv_prod_id, g_expected_isv_prod_id, sizeof(g_expected_isv_prod_id)))
        return -1;

    if (g_verify_isv_svn &&
            memcmp(isv_svn, g_expected_isv_svn, sizeof(g_expected_isv_svn)))
        return -1;

    return 0;
}

/* RA-TLS: mbedTLS-specific callback to verify the x509 certificate */
static int my_verify_callback(void* data, mbedtls_x509_crt* crt, int depth, uint32_t* flags) {
    if (depth != 0) {
        /* the cert chain in RA-TLS consists of single self-signed cert, so we expect depth 0 */
        return MBEDTLS_ERR_X509_INVALID_FORMAT;
    }
    if (flags) {
        /* mbedTLS sets flags to signal that the cert is not to be trusted (e.g., it is not
         * correctly signed by a trusted CA; since RA-TLS uses self-signed certs, we don't care
         * what mbedTLS thinks and ignore internal cert verification logic of mbedTLS */
        *flags = 0;
    }
    return ra_tls_verify_callback_extended_der_f(crt->raw.p, crt->raw.len,
                                                 (struct ra_tls_verify_callback_results*)data);
}

static bool getenv_client_inside_sgx() {
    char* str = getenv("RA_TLS_CLIENT_INSIDE_SGX");
    if (!str)
        return false;

    return !strcmp(str, "1") || !strcmp(str, "true") || !strcmp(str, "TRUE");
}

double get_GM(double *arr){
    double prod = 1;
    double root;
    
    root = (double)1 / (double)NUM_ROUNDS;
    //printf("%lf\n", root);
    for (int i = 0; i < NUM_ROUNDS; i++){
        prod *= arr[i];        
    }
    
    return pow(prod, root);
}

int main(int argc, char** argv) {
    int exit_code;

    for (int i = 0; i < NUM_ROUNDS; i++){
        clock_gettime(CLOCK_MONOTONIC, &t1);
        int ret;
        size_t len;
        exit_code = MBEDTLS_EXIT_FAILURE;
        mbedtls_net_context server_fd;
        uint32_t flags;
        unsigned char buf[1024];
        const char* pers = "ssl_client1";
        bool in_sgx = getenv_client_inside_sgx();

        char* error;
        void* ra_tls_verify_lib = NULL;
        ra_tls_verify_callback_extended_der_f = NULL;
        ra_tls_set_measurement_callback_f = NULL;
        struct ra_tls_verify_callback_results my_verify_callback_results = {0};

        mbedtls_entropy_context entropy;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_ssl_context ssl;
        mbedtls_ssl_config conf;
        mbedtls_x509_crt cacert;

        #if defined(MBEDTLS_DEBUG_C)
            mbedtls_debug_set_threshold(DEBUG_LEVEL);
        #endif

        mbedtls_net_init(&server_fd);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_x509_crt_init(&cacert);
        mbedtls_entropy_init(&entropy);

        if (argc < 2 ||
                (strcmp(argv[1], "native") && strcmp(argv[1], "epid") && strcmp(argv[1], "dcap"))) {
            #ifndef PROFILE
                mbedtls_printf("USAGE: %s native|epid|dcap [SGX measurements]\n", argv[0]);
            #endif
            return 1;
        }

        if (!strcmp(argv[1], "epid")) {
            ra_tls_verify_lib = dlopen("libra_tls_verify_epid.so", RTLD_LAZY);
            if (!ra_tls_verify_lib) {
                #ifndef PROFILE                
                    mbedtls_printf("%s\n", dlerror());
                    mbedtls_printf("User requested RA-TLS verification with EPID but cannot find lib\n");
                #endif
                if (in_sgx) {
                    #ifndef PROFILE
                        mbedtls_printf("Please make sure that you are using client_epid.manifest\n");
                    #endif
                }
                return 1;
            }
        } else if (!strcmp(argv[1], "dcap")) {
            if (in_sgx) {
                /*
                * RA-TLS verification with DCAP inside SGX enclave uses dummies instead of real
                * functions from libsgx_urts.so, thus we don't need to load this helper library.
                */
                ra_tls_verify_lib = dlopen("libra_tls_verify_dcap_gramine.so", RTLD_LAZY);
                if (!ra_tls_verify_lib) {
                    #ifndef PROFILE
                        mbedtls_printf("%s\n", dlerror());
                        mbedtls_printf("User requested RA-TLS verification with DCAP inside SGX but cannot find lib\n");
                        mbedtls_printf("Please make sure that you are using client_dcap.manifest\n");
                    #endif
                    return 1;
                }
            } else {
                void* helper_sgx_urts_lib = dlopen("libsgx_urts.so", RTLD_NOW | RTLD_GLOBAL);
                if (!helper_sgx_urts_lib) {
                    #ifndef PROFILE
                        mbedtls_printf("%s\n", dlerror());
                        mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find helper"
                                    " libsgx_urts.so lib\n");
                    #endif
                    return 1;
                }

                ra_tls_verify_lib = dlopen("libra_tls_verify_dcap.so", RTLD_LAZY);
                if (!ra_tls_verify_lib) {
                    #ifndef PROFILE
                        mbedtls_printf("%s\n", dlerror());
                        mbedtls_printf("User requested RA-TLS verification with DCAP but cannot find lib\n");
                    #endif
                    return 1;
                }
            }
        }

        if (ra_tls_verify_lib) {
            ra_tls_verify_callback_extended_der_f = dlsym(ra_tls_verify_lib,
                                                        "ra_tls_verify_callback_extended_der");
            if ((error = dlerror()) != NULL) {
                #ifndef PROFILE
                    mbedtls_printf("%s\n", error);
                #endif
                return 1;
            }

            ra_tls_set_measurement_callback_f = dlsym(ra_tls_verify_lib, "ra_tls_set_measurement_callback");
            if ((error = dlerror()) != NULL) {
                #ifndef PROFILE
                    mbedtls_printf("%s\n", error);
                #endif
                return 1;
            }
        }

        if (argc > 2 && ra_tls_verify_lib) {
            if (argc != 6) {
                #ifndef PROFILE
                    mbedtls_printf("USAGE: %s %s <expected mrenclave> <expected mrsigner>"
                                " <expected isv_prod_id> <expected isv_svn>\n"
                                "       (first two in hex, last two as decimal; set to 0 to ignore)\n",
                                argv[0], argv[1]);
                #endif
                return 1;
            }

            #ifndef PROFILE
                mbedtls_printf("[ using our own SGX-measurement verification callback"
                            " (via command line options) ]\n");
            #endif

            g_verify_mrenclave   = true;
            g_verify_mrsigner    = true;
            g_verify_isv_prod_id = true;
            g_verify_isv_svn     = true;

            (*ra_tls_set_measurement_callback_f)(my_verify_measurements);

            if (!strcmp(argv[2], "0")) {
                #ifndef PROFILE
                    mbedtls_printf("  - ignoring MRENCLAVE\n");
                #endif
                g_verify_mrenclave = false;
            } else if (parse_hex(argv[2], g_expected_mrenclave, sizeof(g_expected_mrenclave)) < 0) {
                #ifndef PROFILE
                    mbedtls_printf("Cannot parse MRENCLAVE!\n");
                #endif
                return 1;
            }

            if (!strcmp(argv[3], "0")) {
                #ifndef PROFILE
                    mbedtls_printf("  - ignoring MRSIGNER\n");
                #endif
                g_verify_mrsigner = false;
            } else if (parse_hex(argv[3], g_expected_mrsigner, sizeof(g_expected_mrsigner)) < 0) {
                #ifndef PROFILE
                    mbedtls_printf("Cannot parse MRSIGNER!\n");
                #endif
                return 1;
            }

            if (!strcmp(argv[4], "0")) {
                #ifndef PROFILE
                    mbedtls_printf("  - ignoring ISV_PROD_ID\n");
                #endif
                g_verify_isv_prod_id = false;
            } else {
                errno = 0;
                uint16_t isv_prod_id = (uint16_t)strtoul(argv[4], NULL, 10);
                if (errno) {
                    #ifndef PROFILE
                        mbedtls_printf("Cannot parse ISV_PROD_ID!\n");
                    #endif
                    return 1;
                }
                memcpy(g_expected_isv_prod_id, &isv_prod_id, sizeof(isv_prod_id));
            }

            if (!strcmp(argv[5], "0")) {
                #ifndef PROFILE
                    mbedtls_printf("  - ignoring ISV_SVN\n");
                #endif
                g_verify_isv_svn = false;
            } else {
                errno = 0;
                uint16_t isv_svn = (uint16_t)strtoul(argv[5], NULL, 10);
                if (errno) {
                    #ifndef PROFILE
                        mbedtls_printf("Cannot parse ISV_SVN\n");
                    #endif
                    return 1;
                }
                memcpy(g_expected_isv_svn, &isv_svn, sizeof(isv_svn));
            }
        } else if (ra_tls_verify_lib) {
            #ifndef PROFILE
                mbedtls_printf("[ using default SGX-measurement verification callback"
                            " (via RA_TLS_* environment variables) ]\n");
            #endif
            (*ra_tls_set_measurement_callback_f)(NULL); /* just to test RA-TLS code */
        } else {
            #ifndef PROFILE
                mbedtls_printf("[ using normal TLS flows ]\n");
            #endif
        }

        #ifndef PROFILE
            mbedtls_printf("\n  . Seeding the random number generator...");
            fflush(stdout);
        #endif

        ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    (const unsigned char*)pers, strlen(pers));
        if (ret != 0) {
            #ifndef PROFILE
                mbedtls_printf(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
            #endif
            goto exit;
        }

        #ifndef PROFILE
            mbedtls_printf(" ok\n");

            mbedtls_printf("  . Connecting to tcp/%s/%s...", SERVER_NAME, SERVER_PORT);
            fflush(stdout);
        #endif

        ret = mbedtls_net_connect(&server_fd, SERVER_NAME, SERVER_PORT, MBEDTLS_NET_PROTO_TCP);
        if (ret != 0) {
            #ifndef PROFILE
                mbedtls_printf(" failed\n  ! mbedtls_net_connect returned %d\n\n", ret);
            #endif
            goto exit;
        }

        #ifndef PROFILE
            mbedtls_printf(" ok\n");

            mbedtls_printf("  . Setting up the SSL/TLS structure...");
            fflush(stdout);
        #endif

        ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT);
        if (ret != 0) {
            #ifndef PROFILE
                mbedtls_printf(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
            #endif
            goto exit;
        }

        #ifndef PROFILE
            mbedtls_printf(" ok\n");

            mbedtls_printf("  . Loading the CA root certificate ...");
            fflush(stdout);
        #endif

        ret = mbedtls_x509_crt_parse_file(&cacert, CA_CRT_PATH);
        if (ret < 0) {
            #ifndef PROFILE
                mbedtls_printf( " failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", -ret );
            #endif
            goto exit;
        }

        mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
        mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
        #ifndef PROFILE
            mbedtls_printf(" ok\n");
        #endif

        if (ra_tls_verify_lib) {
            /* use RA-TLS verification callback; this will overwrite CA chain set up above */
            #ifndef PROFILE
                mbedtls_printf("  . Installing RA-TLS callback ...");
            #endif
            mbedtls_ssl_conf_verify(&conf, &my_verify_callback, &my_verify_callback_results);
            #ifndef PROFILE
                mbedtls_printf(" ok\n");
            #endif
        }

        mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
        mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

        ret = mbedtls_ssl_setup(&ssl, &conf);
        if (ret != 0) {
            #ifndef PROFILE
                mbedtls_printf(" failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
            #endif
            goto exit;
        }

        ret = mbedtls_ssl_set_hostname(&ssl, SERVER_NAME);
        if (ret != 0) {
            #ifndef PROFILE
                mbedtls_printf(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
            #endif
            goto exit;
        }

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        #ifndef PROFILE
            mbedtls_printf("  . Performing the SSL/TLS handshake...");
            fflush(stdout);
        #endif

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                #ifndef PROFILE
                    mbedtls_printf(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
                    mbedtls_printf("  ! ra_tls_verify_callback_results:\n"
                                "    attestation_scheme=%d, err_loc=%d, \n",
                                my_verify_callback_results.attestation_scheme,
                                my_verify_callback_results.err_loc);
                #endif
                switch (my_verify_callback_results.attestation_scheme) {
                    case RA_TLS_ATTESTATION_SCHEME_EPID:
                        #ifndef PROFILE
                            mbedtls_printf("    epid.ias_enclave_quote_status=%s\n\n",
                                        my_verify_callback_results.epid.ias_enclave_quote_status);
                        #endif
                        break;
                    case RA_TLS_ATTESTATION_SCHEME_DCAP:
                        #ifndef PROFILE
                            mbedtls_printf("    dcap.func_verify_quote_result=0x%x, "
                                        "dcap.quote_verification_result=0x%x\n\n",
                                        my_verify_callback_results.dcap.func_verify_quote_result,
                                        my_verify_callback_results.dcap.quote_verification_result);
                        #endif
                        break;
                    default:
                        #ifndef PROFILE
                            mbedtls_printf("  ! unknown attestation scheme!\n\n");
                        #endif
                        break;
                }

                goto exit;
            }
        }

        #ifndef PROFILE
            mbedtls_printf(" ok\n");

            mbedtls_printf("  . Verifying peer X.509 certificate...");
        #endif

        flags = mbedtls_ssl_get_verify_result(&ssl);
        if (flags != 0) {
            char vrfy_buf[512];
            #ifndef PROFILE
                mbedtls_printf(" failed\n");
            #endif
            mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", flags);
            #ifndef PROFILE
                mbedtls_printf("%s\n", vrfy_buf);
            #endif

            /* verification failed for whatever reason, fail loudly */
            goto exit;
        } else {
            #ifndef PROFILE
                mbedtls_printf(" ok\n");
            #endif
        }

        #ifndef PROFILE
            mbedtls_printf("  > Write to server:");
            fflush(stdout);
        #endif

        len = sprintf((char*)buf, GET_REQUEST);

        while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
                #ifndef PROFILE
                    mbedtls_printf(" failed\n  ! mbedtls_ssl_write returned %d\n\n", ret);
                #endif
                goto exit;
            }
        }

        len = ret;
        #ifndef PROFILE
            mbedtls_printf(" %lu bytes written\n\n%s", len, (char*)buf);

            mbedtls_printf("  < Read from server:");
            fflush(stdout);
        #endif

        do {
            len = sizeof(buf) - 1;
            memset(buf, 0, sizeof(buf));
            ret = mbedtls_ssl_read(&ssl, buf, len);

            if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
                break;

            if (ret < 0) {
                #ifndef PROFILE
                    mbedtls_printf("failed\n  ! mbedtls_ssl_read returned %d\n\n", ret);
                #endif
                break;
            }

            if (ret == 0) {
                #ifndef PROFILE
                    mbedtls_printf("\n\nEOF\n\n");
                #endif
                break;
            }

            len = ret;
            #ifndef PROFILE
                mbedtls_printf(" %lu bytes read\n\n%s", len, (char*)buf);
            #endif
        } while (1);

        mbedtls_ssl_close_notify(&ssl);
        exit_code = MBEDTLS_EXIT_SUCCESS;
        exit:
        #ifdef MBEDTLS_ERROR_C
            if (exit_code != MBEDTLS_EXIT_SUCCESS) {
                char error_buf[100];
                mbedtls_strerror(ret, error_buf, sizeof(error_buf));
                #ifndef PROFILE
                    mbedtls_printf("Last error was: %d - %s\n\n", ret, error_buf);
                #endif
            }
        #endif
            if (ra_tls_verify_lib)
                dlclose(ra_tls_verify_lib);

            mbedtls_net_free(&server_fd);

            mbedtls_x509_crt_free(&cacert);
            mbedtls_ssl_free(&ssl);
            mbedtls_ssl_config_free(&conf);
            mbedtls_ctr_drbg_free(&ctr_drbg);
            mbedtls_entropy_free(&entropy);

        clock_gettime(CLOCK_MONOTONIC, &t2); 
        diff[i] = (double) BILLION * (t2.tv_sec - t1.tv_sec) + (t2.tv_nsec - t1.tv_nsec);
    }

    printf("Geometric mean of %u remote attestations = %0.2lf nanoseconds\n", NUM_ROUNDS, get_GM(diff));
    return exit_code;
}
