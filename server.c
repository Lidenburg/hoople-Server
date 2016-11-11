/*
  Compile with: gcc server.c -o server -Wall -lssl -lcrypto -pthread
*/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "server.h"
#include "crypto.h"

void * acceptSSL(void *);
int checkSerial(char *, char *);
int find_first_count();
int isUserOnline(char *);
int getUsername(char *, char *);

pthread_mutex_t mutex;
struct UserDetails userdetails[MAX_USERS];

int main(int argc, char **argv){
  int sockfd, new_sockfd, port, count = 0, thread_error;
  struct sockaddr_in client_sockaddr;
  socklen_t client_length;
  pthread_t thread[MAX_USERS];
  struct threadInfo threadinfo[MAX_USERS];

  if(argc != 2)
    usage(argv);

  if((port = atoi(argv[1])) < 1024)
    printf("Port number is below 1024, this requires running with elevated priviliges\n");

  sockfd = setupNetworking(port);
  client_length = sizeof(client_sockaddr);

  memset(&userdetails, 0x0, (sizeof(struct UserDetails) * MAX_USERS));

  if(pthread_mutex_init(&mutex, NULL) != 0){
    printf("\n mutex init failed\n");
    exit(1);
  }

  while(1){
    if(count > MAX_USERS)
      break;

    count = find_first_count();
    printf("\nCount is: %d\n", count);

	// Stops execution until new connection is initiated
	// then returns fd into new_sockfd and sockaddr struct into client_sockaddr
    if((new_sockfd = accept(sockfd, (struct sockaddr *)&client_sockaddr, &client_length)) < 0)  
      error("Failed accepting new connection");

    printf("Accepted connection\t count = %d\n", count);

    pthread_mutex_lock(&mutex);
    userdetails[count].CONNECTED = 1;
    pthread_mutex_unlock(&mutex);

    threadinfo[count].TID = count;
    threadinfo[count].sockfd = new_sockfd;
    printf("Created threadinfo[%d]\n", count);

    if((thread_error = pthread_create(&thread[count], NULL, acceptSSL, (void *)&threadinfo[count]))){
      printf("Error creating thread #%d\n", count);
      printf("pthreads error number %d\n", thread_error);
      exit(1);
    }
  }

  if(close(sockfd) == -1)
    error("Failed closing socket in main");

  printf("[!] Reached end of main while(1) loop\n");
  pthread_exit(NULL);
  return 1;
}

int isUserOnline(char *arg){
  int i;
  char *username;

  pthread_mutex_lock(&mutex);

  for(i = 0; i < MAX_USERS; i++){
    username = userdetails[i].USERNAME;
    if(!username) // If null
      continue;

    if(0 == strcmp(username, arg)){
      printf("Found user\n");
      pthread_mutex_unlock(&mutex);

      return 1; // Returns 1 if user is already connected
    }
  }
  printf("No such user connected\n");
  pthread_mutex_unlock(&mutex);

  return 0;
}

int find_first_count(){
  int i;

  pthread_mutex_lock(&mutex);
  for(i = 0; i < MAX_USERS; i++){
    if(userdetails[i].CONNECTED == 0){
      pthread_mutex_unlock(&mutex);
      return i;
    }
  }
  pthread_mutex_unlock(&mutex);
  exit(1);
}

void * acceptSSL(void* arg){   // Read data from socket in seperate function to make threading easier
  struct ChatMessage received_chat_message, proxied_chat_message;
  int fd, length, new_sockfd, TID, written;
  char *username, *receiver = malloc(MAX_USERNAME_LEN + 1);
  SSL_CTX *ctx = NULL;
  SSL *ssl, *receiver_ssl;
  struct threadInfo *threadinfo;

  threadinfo = (struct threadInfo *)arg;
  new_sockfd = threadinfo->sockfd;
  TID = threadinfo->TID;

  printf("[acceptSSL]new_sockfd = %d\n", new_sockfd);
  printf("[acceptSSL]TID = %d\n", TID);


  ctx = InitCTX(ctx);
  loadCerts(ctx);
  // NOTE: this malloc is probably useless
  ssl = malloc(sizeof(SSL));

  // Setup ssl stuff
  if(!(ssl = SSL_new(ctx)) && printf("Error creating ssl struct after accept\n"))
    exit(1);

  if(!SSL_set_fd(ssl, new_sockfd) && printf("Error using ssl_set_fd on new_sockfd\n"))
    exit(1);

  if(SSL_accept(ssl) <= 0){
    printf("SSL_accept failed, someone probably tried to connect using SSLV2/3, did an nmap scan, or didn't supply a key/certificate\n");

    pthread_mutex_lock(&mutex);
    memset(&userdetails[TID], 0x0, sizeof(struct UserDetails));
    pthread_mutex_unlock(&mutex);

    if((fd = SSL_get_fd(ssl)) < 0)
      exit(1);

    close(fd);

    return NULL;
  }

  // Check if the serial of the x509 cert is registered to a user
  username = malloc(MAX_USERNAME_LEN + 1);

  if(!checkSerial(parseCert(ssl), username) && printf("No user matched the given ID\n"))  // The username associated with the serial is returned in username
    goto end;

  // Check if user is already connected
  if(isUserOnline(username) && printf("User is already connected, dropping connection\n"))
    goto end;

  printf("%s connected\n", username);

  // Store these in mutex struct
  pthread_mutex_lock(&mutex);
  userdetails[TID].USERNAME = username;
  userdetails[TID].SSL = ssl;
  pthread_mutex_unlock(&mutex);

  //memset(mesg, 0x0, TOTAL_MAX_MESG_LEN + 1);

  /*
    **********************
    * START OF MAIN LOOP *
    **********************
  */

  // Loops as long as a message is successfully read
  while((length = SSL_read(ssl, &received_chat_message, sizeof(struct ChatMessage))) > 0){

    received_chat_message.MESSAGE[length] = 0; // <paranoid>

    printf("Read %d bytes\n", length);

    printf("[DEBUG]type = %x\n", received_chat_message.MESSAGE_TYPE);

    switch(received_chat_message.MESSAGE_TYPE){
      case CHAT_NORMAL_MESSAGE:
        printf("message: \"%s\"(%d)\n", received_chat_message.MESSAGE, (int)strlen(received_chat_message.MESSAGE));
        proxied_chat_message.MESSAGE_TYPE = CHAT_NORMAL_MESSAGE;
        break;
      case CHAT_FILE_TRANSFER:
        printf("[!] Oops! The message type of this message is not yet implemented! Discarding message\n");
        // proxied_chat_message.MESSAGE_TYPE = CHAT_FILE_TRANSFER;
        continue;
      case CHAT_USER_CONNECTED:
        printf("[!] Oops! The message type of this message is not yet implemented! Discarding message\n");
        // proxied_chat_message.MESSAGE_TYPE = CHAT_USER_CONNECTED;
        continue;
      default:
        printf("[!] This message contained an invalid message type! Discarding message\n");
        continue;
    }


  // Check that the message contains a correctly formatted username
  // getUsername returns the username that the message is to be delivered to in the variable receiver
  if(0 == (getUsername(received_chat_message.MESSAGE, receiver))){
    printf("getUsername failed\n");
    sendErrorMessage(ssl, "Invalid format\n");
    continue;
  }

  // Check if there's an SSL object currently assigned to that username
  if(NULL == (receiver_ssl = getSSLFromUsername(receiver))){
    printf("getSSLFromUsername failed\n");
    sendErrorMessage(ssl, "No such user\n");
    continue;
  }

  // Use pointer magic to only send the message part of the message. +1 for the ':'

  printf("username = %s(%d)\n", username, (int)strlen(username));
  printf("receiver = %s(%d)\n", receiver, (int)strlen(receiver));
  printf("message = %s(%d)\n", received_chat_message.MESSAGE, (int)strlen(received_chat_message.MESSAGE));

  snprintf(proxied_chat_message.MESSAGE, TOTAL_MAX_MESG_LEN, "%s:%s", username, received_chat_message.MESSAGE + strlen(receiver) + 1);
  printf("[DEBUG]new message: \"%s\"\n", proxied_chat_message.MESSAGE);




  // NOTE: write only the size of the actual ChatMessage object, and not the size of A ChatMessage object
  if(0 >= (written = SSL_write(receiver_ssl, &proxied_chat_message, strlen(proxied_chat_message.MESSAGE) + sizeof(int))))
    printf("Error sending message to %s\n", receiver);    // Should probably let the user know if this fails

  printf("Wrote %d bytes\n", written);

  memset(received_chat_message.MESSAGE, 0x0, TOTAL_MAX_MESG_LEN);
} // End of main loop

  printf("%s disconnected\n", username);

  end:
  if((fd = SSL_get_fd(ssl)) < 0)    // The operation can fail if the underlying BIO is not of the correct type
    exit(1);               // This should never happen


  pthread_mutex_lock(&mutex);
  memset(&userdetails[TID], 0x0, sizeof(struct UserDetails));
  pthread_mutex_unlock(&mutex);

  SSL_free(ssl);
  free(username);
  free(receiver);

  if(close(fd) == -1)
    error("Failed closing socket in acceptSSL");

  return NULL;
}

//  wtf have i done here?
int getUsername(char *mesg, char *username){
  int i;

  memset(username, 0x0, MAX_USERNAME_LEN + 1);

  //  TODO: redo this function
  for(i = 0; i < MAX_USERNAME_LEN + 1; i++){
    if(mesg[i] == ':')
      break;
    else if(mesg[i] == 0x0)
      return 0;
    else if(i == MAX_USERNAME_LEN)
      return 0;
  }

  strncpy(username, mesg, i);

  printf("Username: %s\n", username);

  return 1;
}

int checkSerial(char *serial, char *username){
  FILE *users_file;
  char file_serial[1001];
  int result;

  if((users_file = fopen("users.txt", "r")) == NULL)
    error("Failed opening users.txt");

  while(2 == (result = fscanf(users_file, "%s : %s\n", file_serial, username))){
    if(!strcmp(serial, file_serial)){
      //printf("%s\n is the same as\n%s\n", serial, file_serial);
      fclose(users_file);
      free(serial);
      return 1;
    }
    //printf("%s\n is not the same as\n%s\n",serial, file_serial);
  }

  if(result == EOF){
    printf("\nEnd of file reached, no such user\n");
    fclose(users_file);
    return 0;
  }

  printf("\nError reading conf file, invalid format\n");
  fclose(users_file);
  return 0x00;

}
