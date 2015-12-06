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

/*
  Ethernet header size  = 14 bytes
  IPV4 header size = 20 bytes
  TCP header minimum size = 20 bytes, max = 60 bytes

  Ethernet standard MTU = 1500
  theoretical optimal max message length = 1406 bytes
  is for now only 500(+ null terminator)

  NOTE: This does not take into consideration openSSL
*/

void usage(char **argv){
  printf("Usage: %s [PORT]\n", argv[0]);
  printf("\nPort:\t1024-65535\n");
  printf("\tNote: ports below 1024 are possible but require elevated priviliges\n");

  exit(1);
}

void ssl_error(char *mesg){
  printf("%s\n", mesg);
  ERR_print_errors_fp(stderr);

  exit(1);
}

void error(char *mesg){
  perror(mesg);

  exit(1);
}

SSL_CTX * InitCTX(SSL_CTX *ctx){
  const SSL_METHOD *method;
  long flags;

  SSL_library_init();
  SSL_load_error_strings();
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  // Make sure SSLv2 or 3 is never used
  method = SSLv23_method();
  if((ctx = SSL_CTX_new(method)) == NULL)
    ssl_error("Failed creating ctx method");

  flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
  SSL_CTX_set_options(ctx, flags);

  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

  return ctx;
}

void loadCerts(SSL_CTX *ctx){
  if(!SSL_CTX_load_verify_locations(ctx, "rootCA.pem", NULL))
    ssl_error("Failed load_verify_locations");

  if(!SSL_CTX_use_certificate_chain_file(ctx, "rootCA.pem"))
    ssl_error("Failed loading rootCA.pem");

  if(!SSL_CTX_use_PrivateKey_file(ctx, "rootCA-priv.key", SSL_FILETYPE_PEM))
    ssl_error("Failed loading private key");

  if(!SSL_CTX_check_private_key(ctx) && printf("Private key does not match public certificate"))
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
