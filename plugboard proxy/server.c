#include "header.h"     
// server
void connectToservice(char * proxyClientPort, char * serviceIP, char * servicePort, char * key)
{

    //fprintf(stderr, "%s\n",serviceIP);
    //fprintf(stderr, "%s\n",servicePort);
  
    int sockfd, portno,sock;
    struct sockaddr_in serv_addr, client_addr;
    struct hostent *host;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

     if(sockfd < 0) 
        perror("ERROR opening socket");
    
     portno = atoi(proxyClientPort);
     client_addr.sin_family = AF_INET;
     client_addr.sin_port = htons(portno);
     client_addr.sin_addr.s_addr = htonl (INADDR_ANY);


     portno = atoi(servicePort);
     serv_addr.sin_family = AF_INET;
     serv_addr.sin_port = htons(portno);

     if ((host = gethostbyname(serviceIP)) == 0){
        fprintf(stderr, "Could not get host by name!\n");
        exit(EXIT_FAILURE);
      }
     
     serv_addr.sin_addr.s_addr = ((struct in_addr*)(host->h_addr))->s_addr;   

    //fprintf(stderr,"port no:%d",portno);
    //fprintf(stderr, "%d\n",serv_addr.sin_addr.s_addr);
    //fprintf(stderr, "%d\n",serv_addr.sin_port);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) 
        perror("ERROR opening socket");
     if (bind(sockfd, (struct sockaddr *) &client_addr,
              sizeof(client_addr)) < 0) 
              perror("ERROR on binding");    
      listen(sockfd,5);
      unsigned int clientlen = sizeof(client_addr);
        puts("accepting  connections.......");

    while(1){

      sock = (int)accept(sockfd, (struct sockaddr *) &client_addr, &clientlen); 
      if(sock < 0){
       fprintf(stderr,"accept client connection failed\n");
      }else{
        fprintf(stderr,"new client connected!\n");
      }
    
      int ssh_fd,n; 

      ssh_fd = socket(AF_INET, SOCK_STREAM, 0);
      if (connect(ssh_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0){
        fprintf(stderr,"Connection to ssh server failed!\n");
        pthread_exit(0);
      }else {
        fprintf(stderr,"Connection to ssh established!\n");
      }

      
      int flags = fcntl(sock, F_GETFL);

    if (flags == -1){
        printf("read sock 1 flag error!\n");
        printf("Closing connections and exit thread!\n");
        close(sock);
        close(ssh_fd);
      }

    fcntl(sock, F_SETFL, flags | O_NONBLOCK);   // creates a non blocking client socket which connect to pbproxy  client

    

    flags = fcntl(ssh_fd, F_GETFL);             // ssh_fd is the address of the server
    if (flags == -1) {
        printf("read ssh_fd flag error!\n");
        close(sock);
        close(ssh_fd);
      }
    fcntl(ssh_fd, F_SETFL, flags | O_NONBLOCK);  // creates a non blocking server socket which connects to server.
    

      struct ctr_state  state;
      AES_KEY aes_key;
      unsigned char iv[8];

    
  
    if (AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key) < 0) {
        printf("Set encryption key error!\n");
        exit(1);
    }
    

    int ssh_done = 0;
    unsigned char buffer[BUF_SIZE];
 

    bool readiv = false;
    
    while(1){
      //  read the iv here 1 st time so that you do not read it again
      
 
        while ((n = read(sock, buffer, BUF_SIZE)) > 0){
            if(readiv == false){
              if (n < 8) {
                printf("Packet length smaller than 8!\n");
                close(sock);
                close(ssh_fd);
              }
             memcpy(iv, buffer,8);
             //fprintf(stderr, "iv received from client  %s\n",buffer);
             initialize_ctr(&state, iv);
             readiv  = true;
          }
          else{
            //printf("encrypted msg: %s\n", buffer);
            unsigned char decryption[n];
            AES_ctr128_encrypt(buffer, decryption, n, &aes_key, state.ivec, state.ecount, &state.num);
           // printf("decrypted msg: %s\n", decryption);
            write(ssh_fd, decryption, n);
          }
          memset(buffer,0,BUF_SIZE);
            if (n < BUF_SIZE)
                break;
          }
        
        while ((n = read(ssh_fd, buffer, BUF_SIZE)) >= 0){
            if (n > 0) {
               // printf("msg from ssh : %s\n",buffer);
                char *tmp=(char*)malloc(n);
                unsigned char encryption[n];

                AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
                memcpy(tmp,encryption,n);  
                           
              //  write(sock, tmp, n + 8);
                write(sock, tmp, n);
                memset(buffer,0, BUF_SIZE);
                free(tmp);
            }   
           // printf("INFO: Sending data to ssh client\n");
            
            if (ssh_done == 0 && n == 0)
                ssh_done = 1;
            
            if (n < BUF_SIZE)
                break;
       }
       if(ssh_done)
        break;

       }
    }
}
