#include "header.h"
// client
void decryptTextFromServer(char * key, int sockfd);
void encryptStdinText(char * key, int sockfd);
void connectToProxy(char * proxyIp,char * proxyPort,char * key){
    
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    
    portno = atoi(proxyPort);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) 
        perror("ERROR opening socket");

    server = gethostbyname(proxyIp);
    if (server == NULL) {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }

     serv_addr.sin_family = AF_INET;
     serv_addr.sin_port = htons(portno);
     serv_addr.sin_addr.s_addr = ((struct in_addr*)(server->h_addr))->s_addr;


     /* Now connect to the proxy */
    if (connect(sockfd, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0){
        perror("ERROR connecting saahil");
        exit(1);
    }

    fprintf(stderr, "connected");


    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    
    struct ctr_state state;
    unsigned char iv[8];
    AES_KEY aes_key;
   
 

    unsigned char buffer[BUF_SIZE];
    memset(buffer,0, BUF_SIZE);

        
      
        if (!RAND_bytes(iv, 8)) {
                printf("Error generating random bytes.\n");
                exit(1);
        }
        initialize_ctr(&state,iv);

        if (AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key) < 0){
        printf("Set encryption key error!\n");
        exit(1);
      } 
        write(sockfd, iv, 8);

    while(1){

        while ((n = read(STDIN_FILENO, buffer, BUF_SIZE)) > 0){
           // fprintf(stderr, "saahil: %s\n", buffer);
        char *tmp= (char*)malloc(n);
        unsigned char encryption[n];
        AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
        memcpy(tmp,encryption,n);
        write(sockfd, tmp, n);
        free(tmp);
        //fprintf(stderr, "****: \n");
        memset(buffer,0, BUF_SIZE);
        //fprintf(stderr, "****: \n");
       }

        while ((n = read(sockfd, buffer, BUF_SIZE)) > 0) {
            

          //  fprintf(stderr, "message from pbproxy server:%s\n",buffer);

            unsigned char decryption[n];

            AES_ctr128_encrypt(buffer, decryption, n, &aes_key, state.ivec, state.ecount, &state.num);
            
          //  fprintf(stderr, "message from pbproxy server after decryption:%s\n", decryption);

            write(STDOUT_FILENO, decryption, n);
            memset(buffer,0, BUF_SIZE);

            if (n < BUF_SIZE)
                break;
        }

    }    
    close(sockfd);
    return;
}
