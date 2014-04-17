#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <unistd.h>

RSA* existing_user(char* path, uid_t uid);
RSA* create_key(char* path, uid_t uid, int mode);
RSA* new_user(char* path, uid_t uid);
RSA* get_uid_rsa();
void init_openssl();

const int PUBLIC = 1;
const int PRIVATE = 2;
