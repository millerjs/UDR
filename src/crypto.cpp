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

#include "crypto.h"
#include <stdlib.h>

#define N_THREADS 3
#define DEBUG 1

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
  pris("Locking crypto mutex");
  if (mode & CRYPTO_LOCK)
    MUTEX_LOCK(mutex_buf[n]);
  else
    MUTEX_UNLOCK(mutex_buf[n]);
}

// Returns the thread ID
static unsigned long id_function(void){
  return ((unsigned long) THREAD_ID);
}

// Setups up the mutual exclusion for OpenSSL
int THREAD_setup(void){

  pris("Setting up threads");
  mutex_buf = (MUTEX_TYPE*)malloc(CRYPTO_num_locks()*sizeof(MUTEX_TYPE));
  
  if (!mutex_buf)
    return 0;

  for (int i = 0; i < CRYPTO_num_locks(); i++)
    MUTEX_SETUP(mutex_buf[i]);

  CRYPTO_set_id_callback(id_function);
  CRYPTO_set_locking_callback(locking_function);

  pris("Locking and callback functions set");

  return 1;
}

// Cleans up the mutex buffer for openSSL
int THREAD_cleanup(void){

  pris("Cleaning up threads");
  if (!mutex_buf)
    return 0;

  CRYPTO_set_id_callback(NULL);
  CRYPTO_set_locking_callback(NULL);

  for (int i = 0; i < CRYPTO_num_locks(); i ++)
    MUTEX_CLEANUP(mutex_buf[i]);

  free(mutex_buf);
  mutex_buf = NULL;
  return 1;

}

// Wrapper for class encryption function
void *encrypt_threaded(void* _args){

  pris("Encrypting buffer with threading"); 

  // Grab arguments from void*
  e_thread_args* args = (e_thread_args*)_args;

  int *evp_outlen = (int*)malloc(sizeof(int));
  *evp_outlen = args->c->encrypt(args->in, args->out, args->len);
  pthread_exit(NULL);
  
}

int encrypt(char*in, char*out, int len, crypto* c){

  THREAD_setup();

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

  for (int i = 0; i < N_THREADS; i++){
    args[i].in = in+cursor;
    args[i].out = out+cursor;
    args[i].len = cursor+buf_len < len ? buf_len : len-cursor;

    // Ignore unused threads
    if (args[i].len > 0)
      prii(args[i].len);

    args[i].c = c;

    cursor += buf_len;
  }

  pris("Encryption threads initialized");
  pris("Spawning encryption threads");

  void* status;

  // Spawn and run encryption threads
  for(int i = 0; i < N_THREADS; i++) {

    // Ignore unused threads but spawn the others
    if (args[i].len > 0){
      int stat =  pthread_create(&thread[i], &attr, encrypt_threaded, &(args[i])); 
      if (stat) {
	printf("ERROR; return code from pthread_create() is %d\n", stat);
	exit(1);
      }

    }

  }

  pris("Waiting to join encryption threads");

  /* Free attribute and wait for the other threads */
  pthread_attr_destroy(&attr);
  int tot = 0;

  for(int i = 0; i < N_THREADS; i++) {

    if (args[i].len > 0){
      int stat = pthread_join(thread[i], &status);
      if (stat) {
  	fprintf(stderr, "ERROR: return code from pthread_join() is %d\n", *(int*)&stat);
  	exit(1);
      }
    }

  }

  pris("Encryption threads joined");

  THREAD_cleanup();
  
  return 0;

}
