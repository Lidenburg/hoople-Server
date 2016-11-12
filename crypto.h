#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// Functions

char * parseCert(SSL *);
char * randString(int);
int Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *IV, unsigned char *ciphertext); 
void ssl_error(char *);
SSL_CTX * InitCTX(SSL_CTX *);
SSL * getSSLFromUsername(char *);
void loadCerts(SSL_CTX *);

// Variables
extern pthread_mutex_t mutex;
extern struct UserDetails userdetails[MAX_USERS];

// This is horrible
// Returns the serial number
char * parseCert(SSL *ssl){
  X509 *client_cert;
  char *buf;
  char *serial_number = NULL;
  BIGNUM *bn;
  ASN1_INTEGER *serial;

  printf("In parseCert\n");

  serial_number = (char *)malloc(1001);

  // This outcome should never be possible, since the OpenSSL 
  // flags set make sure that the client sends a certificate
  if(NULL == (client_cert = SSL_get_peer_certificate(ssl)))
    exit(1);

  client_cert = SSL_get_peer_certificate(ssl);

  serial = X509_get_serialNumber(client_cert);
  bn = ASN1_INTEGER_to_BN(serial, NULL);

  // TODO: log these failures somewhere
  if(!bn){
    printf("Error converting ASN1INTEGER to BN\n");
    exit(1);
  }

  buf = BN_bn2dec(bn);
  if(!buf){
    printf("Error converting BN to decimal string\n");
    BN_free(bn);
    exit(1);
  }

  if(strlen(buf) >= 1001){
    printf("buffer too short (that's a REALLY long serial!)\n");
    BN_free(bn);
    OPENSSL_free(buf);
    exit(1);
  }

  strncpy(serial_number, buf, 1001);
  BN_free(bn);
  OPENSSL_free(buf);

  printf("serial: %s\n", serial_number);
  return serial_number;
}

char * randString(int length){
  unsigned char buf[length + 1];
  static const char alpha[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  char *randomString;
  int i;

  printf("In randstring\n");

  randomString = (char *)malloc(length + 1);

  if((RAND_load_file("/dev/urandom", 32)) != 32){
    printf("Not enough entropy in /dev/urandom, using RAND_poll instead\n");
    RAND_poll();
  }

  if(!RAND_bytes(buf, length))
    ssl_error("Error generating random bytes in setupEncryption");

  for(i = 0; i < length; i++){
    randomString[i] = alpha[buf[i] % (strlen(alpha) - 1)];
    //printf("randomString [%d] = %c\n", i, randomString[i]);
  }
  randomString[length + 1] = 0x0;
  printf("Random string: %s\n", randomString);
  return randomString;
}

int Encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *IV, unsigned char *ciphertext){
  int len, ciphertext_len;
  EVP_CIPHER_CTX *cipher_ctx;

  // Create the context
  if(!(cipher_ctx = EVP_CIPHER_CTX_new()))
    ssl_error("Error creating new cipher context");

  // Initialize cipher context to 256 bit aes-gcm
  if(1 != EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
    ssl_error("Error setting cipher context to aes_256_gcm");

  // Set IV to 128 bits/16 bytes
  if(1 != EVP_CIPHER_CTX_ctrl(cipher_ctx, EVP_CTRL_GCM_SET_IVLEN, 16, NULL))
    ssl_error("Error setting cipher context IV to 16 bytes");

  //IV = randString(16);    // Generate random IV
  //key = randString(32);   // Generate random key

  // Set IV and key of the context
  if(1 != EVP_EncryptInit_ex(cipher_ctx, NULL, NULL, key, IV))
    ssl_error("Failed seting cipher context's key and IV");

  // Do the actual encryption
    // AES has fixed cipher block size of 128 bits/16 bytes, so the longest possible
    // ciphertext is strlen(message) + 15 (cipher block size - 1)
  if(1 != EVP_EncryptUpdate(cipher_ctx, ciphertext, &len, plaintext, plaintext_len))
    ssl_error("Error encrypting message");

  ciphertext_len = len;

  // Finalize encryption
  if(1 != EVP_EncryptFinal_ex(cipher_ctx, ciphertext + len, &len))  // ciphertext + len assures that we don't overwrite any data but append it instead
    ssl_error("Failed EncryptFinal_ex");

  ciphertext_len += len;

  printf("Encrypted string: \n");
  BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

  EVP_CIPHER_CTX_free(cipher_ctx);
  return ciphertext_len;
}

void ssl_error(char *mesg){
  printf("%s\n", mesg);
  ERR_print_errors_fp(stderr);

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

SSL * getSSLFromUsername(char username[MAX_USERNAME_LEN + 1]){
  int i;
  char* local;

  pthread_mutex_lock(&mutex);
  for(i = 0; i < MAX_USERS; i++){
	// Check that it's not NULL
    if(!(local = userdetails[i].USERNAME))
      continue;

    if(!strcmp(username, local)){
      pthread_mutex_unlock(&mutex);
      return userdetails[i].SSL;
    }
  }
  pthread_mutex_unlock(&mutex);
  return NULL;
}

void loadCerts(SSL_CTX *ctx){
  if(!SSL_CTX_load_verify_locations(ctx, "rootCA.pem", NULL))
    ssl_error("Failed load_verify_locations");

  if(!SSL_CTX_use_certificate_chain_file(ctx, "rootCA.pem"))
    ssl_error("Failed loading rootCA.pem");

  // This isn't actually neccessary for self signed certificates
  SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file("rootCA.pem"));

  if(!SSL_CTX_use_PrivateKey_file(ctx, "rootCA.key", SSL_FILETYPE_PEM))
    ssl_error("Failed loading private key");

  if(!SSL_CTX_check_private_key(ctx) && printf("Private key does not match public certificate"))
    exit(1);
  printf("Loaded all certs\n");
}
