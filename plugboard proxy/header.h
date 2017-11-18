#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <time.h> 
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <netdb.h>
#include <string.h>
#include <fcntl.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdbool.h>
#define BUF_SIZE 4096

struct ctr_state
{
    unsigned char ivec [AES_BLOCK_SIZE];
    unsigned int num;
    unsigned char ecount[AES_BLOCK_SIZE];
};
void * readInput(void * ptr);
void * readFromSocket(void * ptr);
void * serverThread(void * ptr);
void connectToservice(char * proxyClientPort, char * serviceIP, char * servicePort, char * key);
void connectToProxy(char * proxyIp,char * proxyPort,char * key);
void initialize_ctr(struct ctr_state * state, const unsigned char iv[8]);
