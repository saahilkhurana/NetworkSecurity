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
#define aes_block_size 128
#define BUF_SIZE 4096
struct socketcomm{
   int sockfd;
   //int sock;
   struct sockaddr_in ssh_addr;
   char * mykey;
};
struct ctr_state
{
    unsigned char ivec [aes_block_size];
    unsigned int num;
    unsigned char ecount[aes_block_size];
};
void * readInput(void * ptr);
void * readFromSocket(void * ptr);
void * serverThread(void * ptr);
void connectToservice(char * proxyClientPort, char * serviceIP, char * servicePort, char * key);
void connectToProxy(char * proxyIp,char * proxyPort,char * key);
void initialize_ctr(struct ctr_state * state, const unsigned char iv[16]);
