#include "header.h"
// client
void decryptTextFromServer(char * key, int sockfd);
void encryptStdinText(char * key, int sockfd);
void connectToProxy(char * proxyIp,char * proxyPort,char * key){
    
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    //struct socketcomm * ptr;
    int rth, wth;
    
    portno = atoi(proxyPort);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        perror("ERROR opening socket");

    server = gethostbyname(proxyIp);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

     //bzero((char *) &serv_addr, sizeof(serv_addr));
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_port = htons(portno);
     serv_addr.sin_addr.s_addr = ((struct in_addr*)(server->h_addr))->s_addr;

     printf("%d\n",serv_addr.sin_addr.s_addr);

     //bcopy((char *)server->h_addr, (char *)&serv_addr.sin_addr.s_addr, server->h_length);

     /* Now connect to the proxy */
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
        perror("ERROR connecting saahil");
        exit(1);
    }
    //printf("connected \n");
    fprintf(stderr, "connected");

    //ptr = (struct socketcomm *)malloc(sizeof(struct socketcomm));
    //ptr->sockfd = sockfd;
    //ptr->mykey = key;


    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    fcntl(sockfd, F_SETFL, O_NONBLOCK);


    while(1){
    encryptStdinText(key,sockfd);
    decryptTextFromServer(key,sockfd);
    }

    /*int read, write;
    pthread_t rthread, wthread;

    fprintf(stderr, "creating threads now");
    rth = pthread_create(&rthread,NULL, readFromSocket, (void*) ptr);
    if(rth)
    {
        fprintf(stderr,"Error - pthread_create() return code: %d\n",read);
        exit(EXIT_FAILURE);
    }
    wth = pthread_create(&wthread, NULL, readInput, (void*) ptr);
    if(wth)
    {
        fprintf(stderr,"Error - pthread_create() return code: %d\n",write);
        exit(EXIT_FAILURE);
    }
    pthread_join(rthread,NULL);
    pthread_join(wthread,NULL); */

    close(sockfd);
    return;
}

void encryptStdinText(char * key, int sockfd){

    struct ctr_state state;
    unsigned char iv[8];
    AES_KEY aes_key;

   // fprintf(stderr,"\n set encrypt starts\n");
   // fprintf(stderr,"\n key is %s",key);

   
    if (AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key) < 0) {
        printf("Set encryption key error!\n");
        exit(1);
    } 
     
   // printf("set encrypt passed\n");

    

    int n;
    unsigned char buffer[BUF_SIZE];
    memset(buffer,0, BUF_SIZE);

       // read from terminal
       // encrept and send

        
      
        if (!RAND_bytes(iv, 8)) {
                printf("Error generating random bytes.\n");
                exit(1);
        }
        initialize_ctr(&state,iv);
        

        
        //fprintf(stderr, "send a msg to pbproxy\n");
        while ((n = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0){
           // fprintf(stderr, "saahil: %s\n", buffer);
        
        char *tmp = (char*)malloc(n + 8);
        memcpy(tmp, iv, 8);
        unsigned char encryption[n];
       // initialize_ctr(&state,iv);
        AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
        memcpy(tmp + 8, encryption, n);

        // fprintf(stderr, "msg to socket: %s\n", tmp);
        write(sockfd, tmp, n + 8);
        

       // write(sockfd, buffer, n);
        memset(buffer,0, BUF_SIZE);
        free(tmp);
       }
     
}

void decryptTextFromServer(char * key, int sockfd){
   
    int n;
    unsigned char buffer[BUF_SIZE];
    
    struct ctr_state state;
    unsigned char iv[8];
    AES_KEY aes_key;

    //fprintf(stderr,"readFromSocket set encrypt starts\n");
    //fprintf(stderr,"readFromSocket key is %s",key);

    
    if (AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key) < 0) {
        printf("Set encryption key error!\n");
        exit(1);
    }
    

    while ((n = read(sockfd, buffer, BUF_SIZE)) > 0) {
            
            if (n < 8) {
                fprintf(stderr, "Packet length smaller than 8!\n");
                close(sockfd);
                return;
            }

            //printf("message from pbproxy server:%s\n",buffer);
            memcpy(iv, buffer, 8);
            unsigned char decryption[n - 8];
            initialize_ctr(&state, iv);
            AES_ctr128_encrypt(buffer + 8, decryption, n - 8, &aes_key, state.ivec, state.ecount, &state.num);
            

            write(STDOUT_FILENO, decryption, n - 8);

           // write(STDOUT_FILENO, buffer, n);

            if (n < BUF_SIZE)
                break;
        }
}

/*
void * readInput(void * ptr){

    fprintf(stderr, "inside readInput\n");
    struct socketcomm* tmp = (struct socketcomm*) ptr;
    int sockfd = tmp->sockfd;
    //int sock = tmp->sock;
    char * key = tmp->mykey;

    struct ctr_state state;
    unsigned char iv[8];
    AES_KEY aes_key;

    fprintf(stderr,"set encrypt starts\n");
    fprintf(stderr,"key is %s",key);

    if (AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key) < 0) {
        printf("Set encryption key error!\n");
        exit(1);
    }
    printf("set encrypt passed\n");

    if (!RAND_bytes(iv, 8)) {
                printf("Error generating random bytes.\n");
                exit(1);
    }

    int n;
    unsigned char buffer[BUF_SIZE];

    while(1){
       // read from terminal
       // encrept and send

        fprintf(stderr, "send a msg to pbproxy\n");

        while ((n = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0){
        char *tmp = (char*)malloc(n + 8);
        memcpy(tmp, iv, 8);
        unsigned char encryption[n];
        initialize_ctr(&state,iv);
        AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
        memcpy(tmp + 8, encryption, n);
        write(sockfd, tmp, n + 8);

        free(tmp);
     
       }

    }
}

void * readFromSocket (void * ptr) {
    fprintf(stderr, "inside read socket\n");
    struct socketcomm* tmp = (struct socketcomm*) ptr;
    int sockfd = tmp->sockfd;
    //int sock = tmp->sock;
    char * key = tmp->mykey;

    int n;
    unsigned char buffer[BUF_SIZE];
    
    struct ctr_state state;
    unsigned char iv[8];
    AES_KEY aes_key;

    fprintf(stderr,"readFromSocket set encrypt starts\n");
    fprintf(stderr,"readFromSocket key is %s",key);

    if (AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key) < 0) {
        printf("Set encryption key error!\n");
        exit(1);
    }

    while ((n = read(sockfd, buffer, BUF_SIZE)) > 0) {
            if (n < 8) {
                fprintf(stderr, "Packet length smaller than 8!\n");
                close(sockfd);
                return 0;
            }

            memcpy(iv, buffer, 8);
            unsigned char decryption[n - 8];
            initialize_ctr(&state, iv);
            AES_ctr128_encrypt(buffer + 8, decryption, n - 8, &aes_key, state.ivec, state.ecount, &state.num);

            write(STDOUT_FILENO, decryption, n - 8);

            if (n < BUF_SIZE)
                break;
        }

}
*/
