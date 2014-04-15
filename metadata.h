#ifndef METADATA_H
#define METADATA_H

#include <unistd.h>

// Use AES256
#define IVLEN 32
// 256 bytes for PKCS#1 padding of an encrypted AES256 key
#define ENC_KEYLEN 256

struct user_key {
	uid_t owner;
	uint8_t encrypted_key[ENC_KEYLEN];
};

struct metadata {
	uint8_t iv[IVLEN];
	uint16_t n_sub_info;
	struct user_key user_keys[0]; //Varible sized array of user keys.
};

#endif
