#include "header.h"
void initialize_ctr(struct ctr_state * state, const unsigned char iv[8])
{
    /* aes_ctr128_encrypt requires 'num' and 'ecount' set to zero on the
    * first call. */
    state->num = 0;
    memset(state->ecount, 0, AES_BLOCK_SIZE);

    /* Initialise counter in 'ivec' to 0 */
    memset(state->ivec + 8, 0, 8);

    /* Copy IV into 'ivec' */
    memcpy(state->ivec, iv, 8);
}

char * readKeyFromFile(char * filename){
  char * buffer = NULL;
  long n;
  FILE * f = fopen(filename, "rb");
  if (f)
  {
    fseek (f, 0, SEEK_END);
    n = ftell (f);
    fseek (f, 0, SEEK_SET);
    buffer = malloc(n* sizeof(char));
    
    if (buffer){
            fread (buffer, 1, n, f);
        }
        fclose (f);
  }
  return buffer;
}
int main(int argc, char *argv[])
{

    extern char *optarg;
    extern int optind;
    char* filter_exp =  NULL;
    int c, err = 0;
    int revProxy = 0, keyflag =0;
    char * key, *proxyClientPort;
    char * serviceIP, *servicePort;
    char *proxyIp, *proxyPort;
    // WHEN I  am running client mode 
    // i dont need my port coz i get random ports allocated, i need the pbproxy ip and its port to connect to
   // so pbproxy ip port - here ip and port are proxy's ip and port
   // when doing reverse pbproxy -l <port of proxy>  ip and port of the service
    // in our case the service is local host and port is 22.. later on the service can be any machine with an active port.


    while ((c = getopt(argc, argv, "k:l:")) != -1){
        switch (c) {
        case 'k':  
            keyflag = 1;
            key = readKeyFromFile(optarg);
            break;
        case 'l':
            revProxy = 1;
            proxyClientPort = optarg;
            break;
        case '?':
            err = 1;
            break;
        }
    }
    if(err ==1 ){
  perror("nonsense argument %s\n");
            return(2);
    }
    if(keyflag == 0){
    // no key is specified by user";
        char *randomString = NULL;
        char charset [] = "123456789";
        int size = 16;
        randomString = malloc(sizeof(char) * (size +1));
        
        for (int n = 0; n < size; n++) {
            int key = rand() % (int) (sizeof(charset) - 1);
            randomString[n] = charset[n];
        }
        randomString[size] = '\0';
        key = randomString;
    }
    if(revProxy == 1){
       serviceIP = argv[optind];
       servicePort = argv[optind+1];
    // ie. when connecting to service from the proxy. read the service ip and port using optind    
     connectToservice(proxyClientPort,serviceIP,servicePort,key);
    }
    else{
        // i.e when connecting to the proxy from my machine, read the proxy's ip and port using optind
        proxyIp = argv[optind];
        proxyPort = argv[optind+1];
    connectToProxy(proxyIp,proxyPort,key);
    }
    return 0;
}