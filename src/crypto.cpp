#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <limits.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdlib.h>

// #define N_THREADS 20
#define DEBUG 0

#define ENC_MODE 0
#define DEC_MODE 1

#include "crypto.h"

#define pris(x)            fprintf(stderr,"[debug] %s\n",x)   

#define MUTEX_TYPE	   pthread_mutex_t
#define MUTEX_SETUP(x)	   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x)   pthread_mutex_destroy(&x) 
#define MUTEX_LOCK(x)	   pthread_mutex_lock(&x)
#define MUTEX_UNLOCK(x)	   pthread_mutex_unlock(&x)
#define THREAD_ID	   pthread_self()

#define AES_BLOCK_SIZE 8

typedef unsigned char uchar;

typedef struct e_thread_args
{
    uchar *in;
    uchar *out;
    int len;
    int n_threads;
    EVP_CIPHER_CTX* ctx;
} e_thread_args;

static MUTEX_TYPE *mutex_buf = NULL;
static void locking_function(int mode, int n, const char*file, int line);
int THREAD_setup(void);
int THREAD_cleanup(void);
void *enrypt_threaded(void* _args);

void pric(uchar* s, int len)
{
    int i;
    fprintf(stderr, "data: ");
    for (i = 0; i < len/4; i ++){
	fprintf(stderr, "%x ",  s[i]);
    }
    fprintf(stderr, "\n");
}

// void pris(uchar* s){
//     if (DEBUG)
// 	fprintf(stderr, "[crypto debug: %u] %s\n", THREAD_ID, s);
// }

void prii(int i)
{
    if (DEBUG)
	fprintf(stderr, "             -> %d\n", i);
}

const int max_block_size = 64*1024;

// Function for OpenSSL to lock mutex
static void locking_function(int mode, int n, const char*file, int line)
{
    
    /* fprintf(stderr, "[debug] %s\n", "Handling mutex"); */
    if (mode & CRYPTO_LOCK)
	MUTEX_LOCK(mutex_buf[n]);
    else
	MUTEX_UNLOCK(mutex_buf[n]);
}

// Returns the thread ID
static void threadid_func(CRYPTO_THREADID * id)
{
    fprintf(stderr, "[debug] %s\n", "Passing thread ID");
    CRYPTO_THREADID_set_numeric(id, THREAD_ID);
}

// Setups up the mutual exclusion for OpenSSL
int THREAD_setup(void)
{

    fprintf(stderr, "[debug] %s\n", "Setting up threads");
    mutex_buf = (MUTEX_TYPE*)malloc(CRYPTO_num_locks()*sizeof(MUTEX_TYPE));
  
    if (!mutex_buf)
	return 0;

    int i;
    for (i = 0; i < CRYPTO_num_locks(); i++)
	MUTEX_SETUP(mutex_buf[i]);


    /* CRYPTO_set_id_callback(id_function); */
    CRYPTO_THREADID_set_callback(threadid_func);
    CRYPTO_set_locking_callback(locking_function);

    fprintf(stderr, "[debug] %s\n", "Locking and callback functions set");

    return 1;
}


// Cleans up the mutex buffer for openSSL
int THREAD_cleanup(void)
{

    fprintf(stderr, "[debug] %s\n", "Cleaning up threads");
    if (!mutex_buf)
	return 0;

    /* CRYPTO_set_id_callback(NULL); */
    CRYPTO_THREADID_set_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    int i;
    for (i = 0; i < CRYPTO_num_locks(); i ++)
	MUTEX_CLEANUP(mutex_buf[i]);

    return 1;

}

void *update_threaded(void* _args)
{
    // pthread_exit(NULL);
    pris("update_threaded");
    
    int evp_outlen;
    // Grab arguments from void*
    e_thread_args* args = (e_thread_args*)_args;

    fprintf(stderr, "[debug] %s: %s\n", "Encrypting buffer with threading", args->in); 

    if (args->len == 0) {
	if (!EVP_CipherFinal_ex(args->ctx, args->out, &evp_outlen)) {
	    fprintf(stderr, "encryption error\n");
	    exit(EXIT_FAILURE);
	}
	pthread_exit(&evp_outlen);
    }
	
    if(!EVP_CipherUpdate(args->ctx, args->out, &evp_outlen, args->in, args->len)){
	fprintf(stderr, "encryption error\n");
	exit(EXIT_FAILURE);
    }


    // aes_encrypt(args->ctx, args->in, args->out, args->len);

    // pric(args->out, args->len);
  
    fprintf(stderr, "[debug encrypt] %s\n", "EXITING THREAD");
    pthread_exit(&evp_outlen);
  
}


/* int update(int mode, EVP_CIPHER_CTX* c, uchar* in, uchar*out, int len){ */
int update(int mode, e_thread_args args[N_THREADS], uchar* in, uchar*out, unsigned long len)
{

    fprintf(stderr, "[debug] %s\n", "Recieved string to encrypt");
    fprintf(stderr, "[debug] %s\n", "Initializing encryption threads");

    // Create threads
    pthread_t thread[N_THREADS];
    pthread_attr_t attr;
  
    // Make threads joinable
    // pthread_attr_init(&attr);
    // pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    // Assign portions of in/out to each thread arg % AES_BLOCK_SIZE = 0
    size_t buf_len = (size_t) (((double)len)/N_THREADS/AES_BLOCK_SIZE + 1)*AES_BLOCK_SIZE;


    fprintf(stderr, "[debug] %s\n", "Total length"); prii(len);
    fprintf(stderr, "[debug] %s\n", "buf_len"); 
  
    unsigned long cursor = 0;

    int i;
    for (i = 0; i < N_THREADS; i++){
	args[i].in = in+cursor;
	args[i].out = out+cursor;
	args[i].len = cursor+buf_len < len ? buf_len : len-cursor;

	printf("%.*s\n", args[i].len, args[i].in);

	if (args[i].len > 0)
	    printf("%d\n", args[i].len);
	    /* prii(args[i].len); */

	cursor += buf_len;
    }

    fprintf(stderr, "[debug] %s\n", "Encryption threads initialized");

    void* status;

    // Spawn and run encryption threads

    for(i = 0; i < N_THREADS; i++) {
	int stat;
      
	// Ignore unused threads but spawn the others
	if (args[i].len > 0){
	    
	    pris("Launching ship");
	    stat = pthread_create(&thread[i], NULL, update_threaded, &args[i]); 
	    pris("Launched ship");

	    if (stat) {
		fprintf(stderr, "ERROR; return code from pthread_create() is %d\n", stat);
		exit(1);

	    }

	}

    }

    fprintf(stderr, "[debug] %s\n", "Waiting to join encryption threads");

    /* Free attribute and wait for the other threads */
    // pthread_attr_destroy(&attr);
    for(i = 0; i < N_THREADS; i++) {

	if (args[i].len > 0){
	    int stat = pthread_join(thread[i], &status);
	    if (stat) {
		fprintf(stderr, "ERROR: return code from pthread_join()[%d] is %d\n",
			i, *(int*)&stat);
		exit(1);
	    }
	}

    }
  
    fprintf(stderr, "[debug] %s\n", "Encryption threads joined");

    return 0;

}

int encrypt(char* in, char* out, int len, crypto *c)
{

    in = strdup("This is josh and I want to see if this works correctly, but maybe it doesn't and I would be sad.");

    // out = (char*)malloc(len+AES_BLOCK_SIZE);
    
    THREAD_setup();
    
    pris("Creating arg array");
    e_thread_args args[N_THREADS];
    
    for (int i = 0;  i < N_THREADS; i++)
	args[i].ctx = c[i].ctx;

    // update(c->get_direction(), args, (uchar*)in, (uchar*)out, len);

    fprintf(stderr, "in: %s\n", in);
    
    update(EVP_ENCRYPT, args, (uchar*)in, (uchar*)out, len);
    update(EVP_DECRYPT, args, (uchar*)out, (uchar*)in, len);
    fprintf(stderr, "out: %s\n", in);
    

    THREAD_cleanup();
  


    return 0;



}


