#include <openssl/evp.h>
#include <openssl/crypto.h>


#include <time.h>

#include <limits.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdlib.h>
#define DEBUG 0

#include "crypto.h"

#define pris(x)            if (DEBUG)fprintf(stderr,"[crypto] %s\n",x)   

#define MUTEX_TYPE	   pthread_mutex_t
#define MUTEX_SETUP(x)	   pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x)   pthread_mutex_destroy(&x) 
#define MUTEX_LOCK(x)	   pthread_mutex_lock(&x)
#define MUTEX_UNLOCK(x)	   pthread_mutex_unlock(&x)
#define THREAD_ID	   pthread_self()

#define AES_BLOCK_SIZE 8

static MUTEX_TYPE *mutex_buf = NULL;
static void locking_function(int mode, int n, const char*file, int line);

void pric(uchar* s, int len)
{
    int i;
    fprintf(stderr, "data: ");
    for (i = 0; i < len/4; i ++){
	fprintf(stderr, "%x ",  s[i]);
    }
    fprintf(stderr, "\n");
}

void prii(int i)
{
    if (DEBUG)
	fprintf(stderr, "             -> %d\n", i);
}

const int max_block_size = 64*1024;

// Function for OpenSSL to lock mutex
static void locking_function(int mode, int n, const char*file, int line)
{
    pris("LOCKING FUNCTION CALLED");
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


int THREAD_setup(void)
{
    
    pris("Setting up threads");
    mutex_buf = (MUTEX_TYPE*)malloc(CRYPTO_num_locks()*sizeof(MUTEX_TYPE));
  
    if (!mutex_buf)
	return 0;

    int i;
    for (i = 0; i < CRYPTO_num_locks(); i++)
	MUTEX_SETUP(mutex_buf[i]);

    // CRYPTO_set_id_callback(threadid_func);
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


int crypto_update(char* in, char* out, int len, crypto *c)
{

    int evp_outlen = 0;
    int i = c->get_thread_id();
    c->increment_thread_id();
    c->lock(i);

    if (len == 0) {
	
	// FINALIZE CIPHER
	if (!EVP_CipherFinal_ex(&c->ctx[i], (uchar*)in, &evp_outlen)) {
	    	fprintf(stderr, "encryption error\n");
	    	exit(EXIT_FAILURE);
	}

    } else {

    	// [EN][DE]CRYPT
    	if(!EVP_CipherUpdate(&c->ctx[i], (uchar*)in, &evp_outlen, (uchar*)in, len)){
    	    fprintf(stderr, "encryption error\n");
    	    exit(EXIT_FAILURE);
    	}

    	// DOUBLE CHECK
    	if (evp_outlen-len){
    	    fprintf(stderr, "Did not encrypt full length of data [%d-%d]", 
    		    evp_outlen, len);
    	    exit(EXIT_FAILURE);
    	}

    }

    c->unlock(i);

    return evp_outlen;

}


void *crypto_update_thread(void* _args)
{

    int evp_outlen = 0;

    if (!_args){
	fprintf(stderr, "Null argument passed to crypto_update_thread\n");
	exit(1);
    }

    e_thread_args* args = (e_thread_args*)_args;
    int total = 0;
    crypto *c = (crypto*)args->c;
    
    for (int i; i < args->len; i ++){
    	args->out[i] = args->in[i]^args->thread_id;
    }
    
    while (total < args->len){
	
    	if(!EVP_CipherUpdate(args->ctx, args->in+total, &evp_outlen, 
    			     args->out+total, args->len-total)){
    	    fprintf(stderr, "encryption error\n");
    	    exit(EXIT_FAILURE);
    	}
    	total += evp_outlen;
    }
    
    if (total != args->len){
    	fprintf(stderr, "Did not encrypt full length of data [%d-%d]", 
    		evp_outlen, args->len);
    	exit(1);
    }
    
    args->len = total;
    // fprintf(stderr, "unlocking in encrypt %d\n", args->thread_id);
    c->unlock(args->thread_id);

    return NULL;
    // pthread_exit(NULL);
    
}

int pthread_join_disregard_ESRCH(pthread_t thread, crypto*c, int thread_id){

    // fprintf(stderr, "Locking in join %d\n", thread_id);
    c->lock(thread_id);
    // fprintf(stderr, "unlocking in join %d\n", thread_id);
    c->unlock(thread_id);

    return 0;

}

int join_all_encryption_threads(crypto *c){

    if (!c){
	fprintf(stderr, "join_all_encryption_threads passed null pointer\n");
	return 0;
    }

    
    for (int i = 0; i < N_CRYPTO_THREADS; i++){
	pthread_join_disregard_ESRCH(c->threads[i], c, i);
    }
    
    return 0;

}

int pass_to_enc_thread(char* in, char*out, int len, crypto*c){


    // ----------- [ Join the thread we're about to use
    int thread_id = c->get_thread_id();
    c->increment_thread_id();

    // pthread_join_disregard_ESRCH(c->threads[thread_id], c, thread_id);
    // fprintf(stderr, "locking in pass %d\n", thread_id);    
    c->lock(thread_id);

    // ----------- [ Initialize and set thread detached attribute
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    // pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

    // ----------- [ Setup thread
    c->e_args[thread_id].in = (uchar*) in;
    c->e_args[thread_id].out = (uchar*) out;
    c->e_args[thread_id].len = len;
    c->e_args[thread_id].ctx = &c->ctx[thread_id];
    c->e_args[thread_id].c = c;
    c->e_args[thread_id].thread_id = thread_id;

    // ----------- [ Spawn thread

    int ret = 1;
	
    while (ret){
	ret = pthread_create(&c->threads[thread_id],
			     &attr, &crypto_update_thread, 
			     &c->e_args[thread_id]);
    
	if (ret){
	    fprintf(stderr, "Unable to create thread: %d\n", ret);
	    // exit(1);
	}

    }



    return 0;
}

