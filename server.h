#include <errno.h>
#include <stdlib.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define MAX_USERS 16
#define MAX_MESG_LEN 500
#define MAX_USERNAME_LEN 32
#define TOTAL_MAX_MESG_LEN (MAX_MESG_LEN + MAX_USERNAME_LEN + 1)  // NOTE: Not including null byte

// Server command definitions
#define CHAT_NORMAL_MESSAGE 0xFF
#define CHAT_USER_CONNECTED 0xFE
#define CHAT_FILE_TRANSFER 0xFD
#define CHAT_ERROR 0x00

struct ChatMessage{
  int MESSAGE_TYPE;
  char MESSAGE[TOTAL_MAX_MESG_LEN + 1];  // +1 for the null byte
};

struct UserDetails{
  char *USERNAME;
  char *SERIAL;
  SSL *SSL;
  int CONNECTED;
};

struct threadInfo{
  int TID;
  int sockfd;
};

void usage(char **argv){
  printf("Usage: %s [PORT]\n", argv[0]);
  printf("\nPort:\t1024-65535\n");
  printf("\tNote: ports below 1024 are possible but require elevated priviliges\n");

  exit(1);
}

void error(char *mesg){
  perror(mesg);

  exit(1);
}

int setupNetworking(int port){
  int sockfd;
  struct sockaddr_in server_sockaddr;

  /*
    START OF NETWORKING INITIALIZATION
  */

  sockfd = socket(AF_INET, SOCK_STREAM, 0);
  if(sockfd < 0)
    error("Failed creating socket");


  memset(&server_sockaddr, 0x0, sizeof(server_sockaddr)); // Make sure everything is initialized to 0x0 before using
  server_sockaddr.sin_family = AF_INET;                   // Using IPV4
  server_sockaddr.sin_port = htons(port);                 // Listening on port provided by user
  server_sockaddr.sin_addr.s_addr = INADDR_ANY;           // On the address of the local system


  if(bind(sockfd, (struct sockaddr *)&server_sockaddr, sizeof(server_sockaddr)) < 0)
    error("Failed binding socket");

  printf("Listening on socket %d\n", sockfd);
  if(listen(sockfd, 5) < 0)              // Start listening on the socket
    error("Failed to listen");

  return sockfd;
}

void sendNormalMessage(SSL *ssl, char *in_data){
  struct ChatMessage message;

  message.MESSAGE_TYPE = CHAT_NORMAL_MESSAGE;
  strncpy(message.MESSAGE, in_data, MAX_MESG_LEN);

  SSL_write(ssl, &message, strlen(message.MESSAGE) + sizeof(int));
  printf("message written: %s\n", message.MESSAGE);
}

void sendErrorMessage(SSL *ssl, char *in_data){
  struct ChatMessage message;

  message.MESSAGE_TYPE = CHAT_ERROR;

  strncpy(message.MESSAGE, in_data, MAX_MESG_LEN);

  SSL_write(ssl, &message, strlen(message.MESSAGE) + sizeof(int));
}
