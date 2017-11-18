#include "header.h"

void * serverThread(void * ptr){

    if(!ptr) pthread_exit(0);
    
    struct socketcomm * params = (struct socketcomm *) ptr;
    int sock = params->sockfd;                      // contains client socket
    char * key = params->mykey;              // contains key
    struct sockaddr_in ssh_addr = params->ssh_addr;   // contains server address 

    int n;
    int ssh_fd, ssh_done = 0;
    unsigned char buffer[BUF_SIZE];
    
    bzero(buffer, BUF_SIZE);

    ssh_fd = socket(AF_INET, SOCK_STREAM, 0);         // create a socket to comnect to the server

    fprintf(stderr, "%d\n",ssh_addr.sin_addr.s_addr);
    fprintf(stderr, "%d\n",ssh_addr.sin_port);
  

    
    /*if (connect(ssh_fd, (struct sockaddr *)&ssh_addr, sizeof(ssh_addr)) < 0){
        printf("Connection to ssh server failed!\n");
        pthread_exit(0);
    }else {
        printf("Connection to ssh established!\n");
    }
    */
    
    int flags = fcntl(sock, F_GETFL);

    if (flags == -1){
        printf("read sock 1 flag error!\n");
        printf("Closing connections and exit thread!\n");
        close(sock);
        close(ssh_fd);
        free(params);
        pthread_exit(0);
    }

    fcntl(sock, F_SETFL, flags | O_NONBLOCK);   // creates a non blocking client socket which connect to pbproxy  client

    

    flags = fcntl(ssh_fd, F_GETFL);             // ssh_fd is the address of the server
    if (flags == -1) {
        printf("read ssh_fd flag error!\n");
        close(sock);
        close(ssh_fd);
        free(params);
        pthread_exit(0);
    }
    fcntl(ssh_fd, F_SETFL, flags | O_NONBLOCK);  // creates a non blocking server socket which connects to server.
    

    struct ctr_state  state;
    AES_KEY aes_key;
    unsigned char iv[8];

    /*

    if (AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key) < 0) {
        printf("Set encryption key error!\n");
        exit(1);
    }
    */


    while(1){

        while ((n = read(sock, buffer, BUF_SIZE)) > 0){

            if (n < 8) {
                printf("Packet length smaller than 8!\n");
                close(sock);
                close(ssh_fd);
                free(params);
                pthread_exit(0);
            }
            
            /*
            memcpy(iv, buffer, 8);
            unsigned char decryption[n-8];
            initialize_ctr(&state, iv);
            AES_ctr128_encrypt(buffer+8, decryption, n-8, &aes_key, state.ivec, state.ecount, &state.num);
            */
            

            printf("%s\n", buffer);

           // write(ssh_fd, decryption, n-8);

            write(ssh_fd, buffer, n);


            if (n < BUF_SIZE)
                break;
        }
        
        while ((n = read(ssh_fd, buffer, BUF_SIZE)) >= 0){
            if (n > 0) {

                /*
                if(!RAND_bytes(iv, 8)){
                    fprintf(stderr, "Error generating random bytes.\n");
                    exit(1);
                  }

                char *tmp = (char*)malloc(n + 8);
                memcpy(tmp, iv, 8);
                unsigned char encryption[n];
                initialize_ctr(&state, iv);
                AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
                memcpy(tmp+8, encryption, n);
                
                usleep(1000);
                */

               // write(sock, tmp, n + 8);
                write(sock, buffer, n);
                memset(buffer,0, BUF_SIZE);
                //free(tmp);
            }   
            if (ssh_done == 0 && n == 0)
                ssh_done = 1;
            
            if (n < BUF_SIZE)
                break;
       }
    
    }
    printf("Closing connections. Exiting thread!\n");
    close(sock);
    close(ssh_fd);
    free(params);
    pthread_exit(0);  
}       
// server
void connectToservice(char * proxyClientPort, char * serviceIP, char * servicePort, char * key)
{

    fprintf(stderr, "%s\n",serviceIP);
    fprintf(stderr, "%s\n",servicePort);
  
    int sockfd, portno, n,sock;
    struct sockaddr_in serv_addr, client_addr;
    struct hostent *host;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

     if(sockfd < 0) 
        perror("ERROR opening socket");
    
     // bzero((char *) &serv_addr, sizeof(serv_addr));
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

     // bzero((char *) &serv_addr, sizeof(serv_addr));
     
     serv_addr.sin_addr.s_addr = ((struct in_addr*)(host->h_addr))->s_addr;   

    fprintf(stderr,"port no:%d",portno);
    fprintf(stderr, "%d\n",serv_addr.sin_addr.s_addr);
    fprintf(stderr, "%d\n",serv_addr.sin_port);

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
     if (sockfd < 0) 
        perror("ERROR opening socket");
     if (bind(sockfd, (struct sockaddr *) &client_addr,
              sizeof(client_addr)) < 0) 
              perror("ERROR on binding");    
      listen(sockfd,5);
      unsigned int clientlen = sizeof(client_addr);


    while(1){

      sock = (int)accept(sockfd, (struct sockaddr *) &client_addr, &clientlen);       
      int ssh_fd; 

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
        //free(params);
        pthread_exit(0);
    }

    fcntl(sock, F_SETFL, flags | O_NONBLOCK);   // creates a non blocking client socket which connect to pbproxy  client

    

    flags = fcntl(ssh_fd, F_GETFL);             // ssh_fd is the address of the server
    if (flags == -1) {
        printf("read ssh_fd flag error!\n");
        close(sock);
        close(ssh_fd);
        //free(params);
        pthread_exit(0);
    }
    fcntl(ssh_fd, F_SETFL, flags | O_NONBLOCK);  // creates a non blocking server socket which connects to server.
    


      pthread_t th;
      struct socketcomm * threadParam;

      struct ctr_state  state;
      AES_KEY aes_key;
      unsigned char iv[8];

    
  
    if (AES_set_encrypt_key((const unsigned char *)key, 128, &aes_key) < 0) {
        printf("Set encryption key error!\n");
        exit(1);
    }
    

    int ssh_done = 0;
    unsigned char buffer[BUF_SIZE];
    printf("accepting  connections\n");
    
    while(1){
 
        while ((n = read(sock, buffer, BUF_SIZE)) > 0){

            if (n < 8) {
                printf("Packet length smaller than 8!\n");
                close(sock);
                close(ssh_fd);
              //  free(params);
                pthread_exit(0);
            }

          //  printf("encrypted msg: %s\n", buffer);
            
            
            memcpy(iv, buffer, 8);
            unsigned char decryption[n-8];
            initialize_ctr(&state, iv);
            AES_ctr128_encrypt(buffer+8, decryption, n-8, &aes_key, state.ivec, state.ecount, &state.num);
            
            

          //  printf("%s\n", buffer);
          //  printf("decrypted msg: %s\n", decryption);

            write(ssh_fd, decryption, n-8);

          //  write(ssh_fd, buffer, n);


            if (n < BUF_SIZE)
                break;
        }
        
        while ((n = read(ssh_fd, buffer, BUF_SIZE)) >= 0){
            if (n > 0) {
               // printf("msg from ssh : %s\n",buffer);
                
                if(!RAND_bytes(iv, 8)){
                    fprintf(stderr, "Error generating random bytes.\n");
                    exit(1);
                  }

                char *tmp = (char*)malloc(n + 8);
                memcpy(tmp, iv, 8);
                unsigned char encryption[n];
                initialize_ctr(&state, iv);
                AES_ctr128_encrypt(buffer, encryption, n, &aes_key, state.ivec, state.ecount, &state.num);
                memcpy(tmp+8, encryption, n);
                
                //usleep(1000);
                
               // printf("encrypted message to client %s\n", tmp);
                write(sock, tmp, n + 8);
               // write(sock, buffer, n);
                memset(buffer,0, BUF_SIZE);
                //free(tmp);
            }   
           // printf("INFO: Sending data to ssh client\n");
            
            if (ssh_done == 0 && n == 0)
                ssh_done = 1;
            
            if (n < BUF_SIZE)
                break;
       }





      /*
        threadParam = (struct socketcomm *) malloc(sizeof(struct socketcomm));
        printf("accepting  connections\n");
        int newsockfd = (int)accept(sockfd, (struct sockaddr *) &client_addr, &clientlen);  

        
        // now you would want to connect to the server using this new socket
        threadParam->sockfd = newsockfd;
        threadParam->ssh_addr = serv_addr;   // pushing the server address on the struct
        threadParam->mykey = key;

        printf("creating a server thread\n");

        if (newsockfd > 0) {
          //  pthread_create(&th, 0, serverThread, (void *)threadParam);
          //  pthread_detach(th);
        } else {
            perror("ERROR on accept");
            free(threadParam);
        }
        */

       }
    }
}
