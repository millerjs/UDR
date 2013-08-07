/*****************************************************************************
Copyright 2012 Laboratory for Advanced Computing at the University of Chicago

This file is part of UDR.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions
and limitations under the License.
*****************************************************************************/
#ifndef CRYPTO_H
#define CRYPTO_H

#define PASSPHRASE_SIZE 32
#define HEX_PASSPHRASE_SIZE 64
#define EVP_ENCRYPT 1
#define EVP_DECRYPT 0
#define CTR_MODE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <limits.h>
#include <iostream>
#include <unistd.h>

#define MUTEX_TYPE		pthread_mutex_t
#define MUTEX_SETUP(x)		pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x)	pthread_mutex_destroy(&x) 
#define MUTEX_LOCK(x)		pthread_mutex_lock(&x)
#define MUTEX_UNLOCK(x)		pthread_mutex_unlock(&x)
#define THREAD_ID		pthread_self()

static MUTEX_TYPE *mutex_buf = NULL;
static void locking_function(int mode, int n, const char*file, int line);
/* static unsigned long id_function(void); */
static void* id_function(CRYPTO_THREADID * id);
int THREAD_setup(void);
int THREAD_cleanup(void);
void *enrypt_threaded(void* _args);

using namespace std;

class crypto
{
    private:
    //BF_KEY key;
    unsigned char ivec[ 1024 ];
    int direction;

    int passphrase_size;
    int hex_passphrase_size;

    // EVP stuff
    EVP_CIPHER_CTX ctx;

    public:

    crypto(int direc, int len, unsigned char* password, char *encryption_type)
    {
        //free_key( password ); can't free here because is reused by threads
        const EVP_CIPHER *cipher;

        //aes-128|aes-256|bf|des-ede3
        //log_set_maximum_verbosity(LOG_DEBUG);
        //log_print(LOG_DEBUG, "encryption type %s\n", encryption_type);

        if (strncmp("aes-128", encryption_type, 8) == 0) {
            //log_print(LOG_DEBUG, "using aes-128 encryption\n");
#ifdef OPENSSL_HAS_CTR
            if (CTR_MODE)
                cipher = EVP_aes_128_ctr();
            else
#endif
                cipher = EVP_aes_128_cfb();
        }
        else if (strncmp("aes-192", encryption_type, 8) == 0) {
            //log_print(LOG_DEBUG, "using aes-192 encryption\n");
#ifdef OPENSSL_HAS_CTR
            if (CTR_MODE)
                cipher = EVP_aes_192_ctr();
            else
#endif
                cipher = EVP_aes_192_cfb();
        }
        else if (strncmp("aes-256", encryption_type, 8) == 0) {
            //log_print(LOG_DEBUG, "using aes-256 encryption\n");
#ifdef OPENSSL_HAS_CTR
            if (CTR_MODE)
                cipher = EVP_aes_256_ctr();
            else
#endif
                cipher = EVP_aes_256_cfb();
        }
        else if (strncmp("des-ede3", encryption_type, 9) == 0) {
            // apparently there is no 3des nor bf ctr
            cipher = EVP_des_ede3_cfb();
            //log_print(LOG_DEBUG, "using des-ede3 encryption\n");
        }
        else if (strncmp("bf", encryption_type, 3) == 0) {
            cipher = EVP_bf_cfb();
            //log_print(LOG_DEBUG, "using blowfish encryption\n");
        }
        else {
            fprintf(stderr, "error unsupported encryption type %s\n",
                encryption_type);
            exit(EXIT_FAILURE);
        }

        memset(ivec, 0, 1024);

        direction = direc;
        // EVP stuff
        EVP_CIPHER_CTX_init(&ctx);

        if (!EVP_CipherInit_ex(&ctx, cipher, NULL, password, ivec, direc)) {
            fprintf(stderr, "error setting encryption scheme\n");
            exit(EXIT_FAILURE);
        }
    }

//    ~crypto()
//    {
//        // i guess thread issues break this but it needs to be done
//        //TODO: find out why this is bad and breaks things
//        EVP_CIPHER_CTX_cleanup(&ctx);
//    }


    // Returns how much has been encrypted and will call encrypt final when
    // given len of 0
    int encrypt(char *in, char *out, int len)
    {
        int evp_outlen;
	
        if (len == 0) {
            if (!EVP_CipherFinal_ex(&ctx, (unsigned char *)out, &evp_outlen)) {
                fprintf(stderr, "encryption error\n");
                exit(EXIT_FAILURE);
            }
            return evp_outlen;
        }
	
        if(!EVP_CipherUpdate(&ctx, (unsigned char *)out, &evp_outlen, (unsigned char *)in, len))
	  {
            fprintf(stderr, "encryption error\n");
            exit(EXIT_FAILURE);
	  }
        return evp_outlen;
    }

    
};

typedef struct e_thread_args{
  char *in;
  char *out;
  int len;
  int n_threads;
  crypto* c;

} e_thread_args;

int encrypt(char*in, char*out, int len, crypto* c);

#endif
/* Threaded instances */

