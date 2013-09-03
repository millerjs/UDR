#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <limits.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdlib.h>
#define DEBUG 1

#include "crypto.h"

#define pris(x)            if (DEBUG)fprintf(stderr,"[crypto] %s\n",x)   

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

    pris("Setting up threads");
    mutex_buf = (MUTEX_TYPE*)malloc(CRYPTO_num_locks()*sizeof(MUTEX_TYPE));
  
    if (!mutex_buf)
	return 0;

    int i;
    for (i = 0; i < CRYPTO_num_locks(); i++)
	MUTEX_SETUP(mutex_buf[i]);


    /* CRYPTO_set_id_callback(id_function); */
    CRYPTO_THREADID_set_callback(threadid_func);
    CRYPTO_set_locking_callback(locking_function);

    pris("Locking and callback functions set");

    return 0;
}


// Cleans up the mutex buffer for openSSL
int THREAD_cleanup(void)
{

    pris("Cleaning up threads");
    if (!mutex_buf)
	return 0;

    /* CRYPTO_set_id_callback(NULL); */
    CRYPTO_THREADID_set_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    int i;
    for (i = 0; i < CRYPTO_num_locks(); i ++)
	MUTEX_CLEANUP(mutex_buf[i]);

    return 0;

}

void *update_thread(void* _args)
{

    pris("entering update_threaded");
    

    e_thread_args* args = (e_thread_args*)_args;

    int evp_outlen;
    // int* evp_outlen = (int*)malloc(sizeof(int));
	
    if(!EVP_CipherUpdate(args->ctx, args->out, &evp_outlen, args->in, args->len)){
	fprintf(stderr, "encryption error\n");
	exit(EXIT_FAILURE);
    }

    if (evp_outlen-args->len){
	fprintf(stderr, "Did not encrypt full length of data [%d-%d]", 
		evp_outlen, args->len);
	exit(1);
    }

    pthread_exit(&evp_outlen);
  
}


/* int update(int mode, EVP_CIPHER_CTX* c, uchar* in, uchar*out, int len){ */
int update(e_thread_args args[N_THREADS], uchar* in, uchar*out, unsigned long len)
{

    pris("Recieved string to encrypt");

    // Create threads
    pthread_t thread[N_THREADS];
    pthread_attr_t attr;
  
    // Make threads joinable
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    // Assign portions of in/out to each thread arg % AES_BLOCK_SIZE = 0
    size_t buf_len = (size_t) (((double)len)/N_THREADS/AES_BLOCK_SIZE + 1)*AES_BLOCK_SIZE;
    // size_t buf_len = (size_t) (((double)len)/N_THREADS + 1);

    pris("Total length"); prii(len);
  
    unsigned long cursor = 0;

    int i;
    for (i = 0; i < N_THREADS; i++){
	args[i].in = in+cursor;
	args[i].out = out+cursor;
	args[i].len = cursor+buf_len < len ? buf_len : len-cursor;

	if (args[i].len>0)
	    pris("Buffer length"); prii(args[i].len);
	
	cursor += args[i].len;
	pris("cursor");prii(cursor);
    }

    pris("Encryption threads initialized");

    // Spawn and run encryption threads
    for(i = 0; i < N_THREADS; i++) {
      
	// Ignore unused threads but spawn the others
	if (args[i].len > 0){
	    
	    int stat = pthread_create(&thread[i], NULL, update_thread, &args[i]); 
	    
	    if (stat) {
		fprintf(stderr, "ERROR; return code from pthread_create() is %d\n", stat);
		exit(1);
		
	    }

	}

    }

    pris("Waiting to join encryption threads");

    int evp_outlen = 0;

    /* Free attribute and wait for the other threads */
    pthread_attr_destroy(&attr);
    for(i = 0; i < N_THREADS; i++) {

	void*status;
	if (args[i].len > 0){
	    int stat = pthread_join(thread[i], &status);
	    if (stat) {
		fprintf(stderr, "ERROR: return code from pthread_join()[%d] is %d\n",
			i, *(int*)&stat);
		exit(1);
	    }
	}
	evp_outlen += *(int*)status;
	
    }
  
    pris("Encryption threads joined");
    return evp_outlen;

}

int encrypt(char* in, char* out, int len, crypto *c)
{
    
    int evp_outlen = 0;
    if (len == 0) {
	for (int i = 0; i < N_THREADS; i ++){
	    if (!EVP_CipherFinal_ex(&c->ctx[i], (uchar*)out, &evp_outlen)) {
	    	fprintf(stderr, "encryption error\n");
	    	exit(EXIT_FAILURE);
	    }
	}

    } else {
	e_thread_args args[N_THREADS];
	for (int i = 0;  i < N_THREADS; i++)
	    args[i].ctx = &c->ctx[i];
	evp_outlen = update(args, (uchar*)in, (uchar*)out, len);

    }

    return evp_outlen;



}


