#include <openssl/evp.h>
#include <openssl/crypto.h>

#include <limits.h>
#include <unistd.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdlib.h>

#define N_THREADS 10
#define DEBUG 0

#define ENC_MODE 0
#define DEC_MODE 1

#define MUTEX_TYPE		pthread_mutex_t
#define MUTEX_SETUP(x)		pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x)	pthread_mutex_destroy(&x) 
#define MUTEX_LOCK(x)		pthread_mutex_lock(&x)
#define MUTEX_UNLOCK(x)		pthread_mutex_unlock(&x)
#define THREAD_ID		pthread_self()

#define AES_BLOCK_SIZE 8

typedef struct e_thread_args{
    char *in;
    char *out;
    int len;
    int n_threads;
    EVP_CIPHER_CTX* c;
} e_thread_args;

static MUTEX_TYPE *mutex_buf = NULL;
static void locking_function(int mode, int n, const char*file, int line);
/* static unsigned long id_function(void); */
static void* id_function(CRYPTO_THREADID * id);
int THREAD_setup(void);
int THREAD_cleanup(void);
void *enrypt_threaded(void* _args);


void pric(char* s, int len){
    int i;
    fprintf(stderr, "data: ");
    for (i = 0; i < len/4; i ++){
	fprintf(stderr, "%x ",  s[i]);
    }
    fprintf(stderr, "\n");

  
}

void pris(char* s){
    if (DEBUG)
	fprintf(stderr, "[crypto debug: %u] %s\n", THREAD_ID, s);
}

void prii(int i){
    if (DEBUG)
	fprintf(stderr, "             -> %d\n", i);
}

const int max_block_size = 64*1024;

// Function for OpenSSL to lock mutex
static void locking_function(int mode, int n, const char*file, int line){
    /* pris("Handling mutex"); */
    if (mode & CRYPTO_LOCK)
	MUTEX_LOCK(mutex_buf[n]);
    else
	MUTEX_UNLOCK(mutex_buf[n]);
}

// Returns the thread ID
static void threadid_func(CRYPTO_THREADID * id){
    pris("Passing thread ID");
    CRYPTO_THREADID_set_numeric(id, THREAD_ID);
}

// Setups up the mutual exclusion for OpenSSL
int THREAD_setup(void){

    pris("Setting up threads");
    mutex_buf = (MUTEX_TYPE*)malloc(CRYPTO_num_locks()*sizeof(MUTEX_TYPE));
  
    if (!mutex_buf)
	return 0;

    int i;
    for (i = 0; i < CRYPTO_num_locks(); i++)
	MUTEX_SETUP(mutex_buf[i]);


    // CRYPTO_set_id_callback(id_function);
    CRYPTO_THREADID_set_callback(threadid_func);
    CRYPTO_set_locking_callback(locking_function);

    pris("Locking and callback functions set");

    return 1;
}


// Cleans up the mutex buffer for openSSL
int THREAD_cleanup(void){

    pris("Cleaning up threads");
    if (!mutex_buf)
	return 0;

    // CRYPTO_set_id_callback(NULL);
    CRYPTO_THREADID_set_callback(NULL);
    CRYPTO_set_locking_callback(NULL);

    int i;
    for (i = 0; i < CRYPTO_num_locks(); i ++)
	MUTEX_CLEANUP(mutex_buf[i]);


    return 1;

}

unsigned char *aes_encrypt(EVP_CIPHER_CTX *e, unsigned char *plaintext, char*out, int len)
{
    int c_len = len + AES_BLOCK_SIZE;
    int f_len = 0;
    EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_EncryptUpdate(e, out, &c_len, plaintext, len);
    EVP_EncryptFinal_ex(e, out+c_len, &f_len);
    return out;
}

unsigned char *aes_decrypt(EVP_CIPHER_CTX *e, char* plaintext, char *ciphertext, int len)
{
    int p_len = len, f_len = 0;
    EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL);
    EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, len);
    EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len);
    return plaintext;
}

// Wrapper for class encryption function
void *encrypt_threaded(void* _args){

    pris("Encrypting buffer with threading"); 

    // Grab arguments from void*
    e_thread_args* args = (e_thread_args*)_args;

    /* int *evp_outlen = (int*)malloc(sizeof(int)); */
    /* pris(args->in); */

    /* memcpy(args->out, aes_encrypt(args->c, args->in, args->len), args->len); */
    aes_encrypt(args->c, args->in, args->out, args->len);
    /* args->out = aes_encrypt(args->c, args->in, args->len); */
    pric(args->out, args->len);
  
    pris("EXITING THREAD");
    pthread_exit(NULL);
  
}

// Wrapper for class encryption function
void *decrypt_threaded(void* _args){

    pris("Decrypting buffer with threading"); 

    // Grab arguments from void*
    e_thread_args* args = (e_thread_args*)_args;

    /* int *evp_outlen = (int*)malloc(sizeof(int)); */
    /* pris(args->in); */

    /* memcpy(args->out, aes_encrypt(args->c, args->in, args->len), args->len); */
    aes_decrypt(args->c, args->in, args->out, args->len);
    /* args->out = aes_encrypt(args->c, args->in, args->len); */
    /* pric(args->out, args->len); */
  
    pris("EXITING THREAD");
    pthread_exit(NULL);
  
}


int update(int mode, EVP_CIPHER_CTX* c, char* in, char*out, int len){

    /* THREAD_setup(); */

    pris("Recieved string to encrypt");
    pris("Initializing encryption threads");

    // Create threads
    pthread_t thread[N_THREADS];
    pthread_attr_t attr;
  
    // Make threads joinable
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

    // Create thread args
    e_thread_args args[N_THREADS];
  
    // Assign portions of in/out to each thread arg
    size_t buf_len = (size_t) (((double)len)/N_THREADS + 1);

    pris("Total length"); prii(len);
    pris("buf_len"); 
  
    int cursor = 0;

    int i;
    for (i = 0; i < N_THREADS; i++){
	args[i].c = c;
	args[i].in = in+cursor;
	args[i].out = out+cursor;
	args[i].len = cursor+buf_len < len ? buf_len : len-cursor;

	printf("%.*s\n", args[i].len, args[i].in);

	if (args[i].len > 0)
	    prii(args[i].len);

	cursor += buf_len;
    }

    pris("Encryption threads initialized");
    pris("Spawning encryption threads");

    void* status;

    // Spawn and run encryption threads

    for(i = 0; i < N_THREADS; i++) {
	int stat;
      
	// Ignore unused threads but spawn the others
	if (args[i].len > 0){
	    if (mode == ENC_MODE)
		stat = pthread_create(&thread[i], &attr, encrypt_threaded, &(args[i])); 
	    else
		stat = pthread_create(&thread[i], &attr, decrypt_threaded, &(args[i])); 


	    if (stat) {
		printf("ERROR; return code from pthread_create() is %d\n", stat);
		exit(1);

	    }

	}

    }

    pris("Waiting to join encryption threads");

    /* Free attribute and wait for the other threads */
    /* pthread_attr_destroy(&attr); */

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
  
    pris("Encryption threads joined");

    /* THREAD_cleanup(); */

    return 0;

}

int aes_init(unsigned char *key_data, int key_data_len, 
	     unsigned char *salt, EVP_CIPHER_CTX *e_ctx, 
	     EVP_CIPHER_CTX *d_ctx){

    int i, nrounds = 5;
    unsigned char key[32], iv[32];

    EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);

    EVP_CIPHER_CTX_init(e_ctx);
    EVP_EncryptInit_ex(e_ctx, EVP_aes_256_cbc(), NULL, key, iv);
    EVP_CIPHER_CTX_init(d_ctx);
    EVP_DecryptInit_ex(d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

    return 0;
}

int main(int argc, char **argv)
{


    char *plaintext = argv[1];
    int len = strlen(plaintext)+1;
    char *ciphertext = (char*)malloc(len+AES_BLOCK_SIZE);

    THREAD_setup();

    EVP_CIPHER_CTX en, de;
    unsigned int salt[] = {12345, 54321};
    unsigned char *key_data = (unsigned char*)"hello";
    int key_data_len = strlen((char*)key_data);

    if (aes_init(key_data, key_data_len, (unsigned char *)&salt, &en, &de)) {
	printf("Couldn't initialize AES cipher\n");
	return -1;
    }

    /* ciphertext = aes_encrypt(&en, plaintext, len); */
    /* pric(ciphertext, len); */
    update(ENC_MODE, &en, plaintext, ciphertext, len);
    /* pric(ciphertext, len); */
    /* aes_decrypt(&de, plaintext, ciphertext, len); */
    update(DEC_MODE, &de, plaintext, ciphertext, len);
    /* plaintext = aes_decrypt(&de, ciphertext, len); */

    printf("Encrypted: %s\n",ciphertext);
    printf("Decrypted: %s\n\n",plaintext);


    EVP_CIPHER_CTX_cleanup(&en);
    EVP_CIPHER_CTX_cleanup(&de);



    THREAD_cleanup();
  


    return 0;



}
  
