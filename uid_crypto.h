#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <unistd.h>

RSA* existing_user(char* path);
RSA* create_keypair(char* path);
RSA* new_user(char* path);
RSA* get_uid_rsa();
void init_openssl();
