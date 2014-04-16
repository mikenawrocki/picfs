#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/stat.h>

#include "metadata.h"
#include "crypto.h"

RSA *keypair;

int metadata_uid_exists(FILE *metadata, uid_t uid)
{
	int i, read_num;
	struct metadata md;
	struct user_key uk;

	rewind(metadata);
	read_num = fread(&md, sizeof(md), 1, metadata);
	if(read_num < 1 || ferror(metadata))
		return 0;

	for(i = 0; i < md.n_user_keys && !feof(metadata); i++) {
		fread(&uk, sizeof(uk), 1, metadata);
		if(uk.owner == uid)
			return 1; //Already have permission.
	}
	return 0;
}

int decrypt_metadata(FILE *metadata, char *key_buf, char *iv_buf, size_t keylen,
		size_t ivlen)
{
	int read_num, i, ret = 0;
	struct metadata md;
	struct user_key uk;
	char *err = NULL;

	uid_t owner_uid = getuid();

	rewind(metadata);
	read_num = fread(&md, sizeof(md), 1, metadata);
	if(read_num < 1 || ferror(metadata))
		return -1;

	for(i = 0; i < md.n_user_keys; i++) {
		fread(&uk, sizeof(uk), 1, metadata);
		if(uk.owner == owner_uid)
			break;
	}

	if(i == md.n_user_keys) {
		return -1; //Invalid UID
	}

	if(iv_buf) {
		memcpy(iv_buf, md.iv, IVLEN);
	}

	err = malloc(130);
	if((ret = RSA_private_decrypt(ENC_KEYLEN, (unsigned char*)uk.encrypted_key,
					(unsigned char*)key_buf, keypair,
					RSA_PKCS1_OAEP_PADDING)) < 0) {
		ERR_load_crypto_strings();
		ERR_error_string(ERR_get_error(), err);
		fprintf(stderr, "Error decrypting message: %s\n", err);
		ret = -1;
	}
	printf("Decrypted message: %s\n", key_buf);
	free(err);
	return ret;
}

int encrypt_symmetric_key(uid_t target, const char *key, size_t key_len,
		char *buf, size_t buf_len)
{
	int ret = 0;
	char pub_key_path[PATH_MAX];
	snprintf(pub_key_path, PATH_MAX, "keys/%d/public", target);
	FILE *public = fopen(pub_key_path, "r");
	RSA *new_key = NULL;
	if(!public) {
		ret = -1;
		goto cleanup;
	}

	PEM_read_RSA_PUBKEY(public, &new_key, NULL, NULL);
	if(!new_key) {
		ret = -2;
		goto cleanup;
	}

	if((ret = RSA_public_encrypt(key_len, (unsigned char*)key,
					(unsigned char*)buf,
					new_key,
					RSA_PKCS1_OAEP_PADDING)) < 0) {
		ret = -3;
	}
cleanup:
	fclose(public);
	RSA_free(new_key);
	return ret;
}

int write_new_user_key(FILE *metadata, struct user_key *uk)
{
	int read_num, write_len, ret = 0;
	struct metadata md;

	rewind(metadata);
	read_num = fread(&md, sizeof(md), 1, metadata);
	if(read_num < 1 || ferror(metadata))
		return -1;

	++md.n_user_keys;
	rewind(metadata);
	write_len = fwrite(&md, sizeof(md), 1, metadata);
	if(write_len < 1 || ferror(metadata)) {
		ret = -1;
	}
	else {
		fseek(metadata, 0, SEEK_END);
		fwrite(uk, sizeof(*uk), 1, metadata);
	}

	return ret;
}

int create_metadata_file(const char *path, const char *IV)
{
	struct metadata md;
	FILE *metadata = fopen(path, "w+");
	if(!metadata)
		return -1;
	memcpy(md.iv, IV, IVLEN);
	md.n_user_keys = 0;
	fwrite(&md, sizeof(md), 1, metadata);
	fflush(metadata);
	fclose(metadata);
	return 0;
}

int add_user_key(FILE *metadata, uid_t uid, char *key)
{
	int encrypt_len, ret = 0;
	int text_len = 32;
	struct user_key uk;
	uk.owner = uid;

	if(metadata_uid_exists(metadata, uid))
		return 0;

	if(!key) {
		key = malloc(AES256_KEYLEN);
		text_len = decrypt_metadata_key(metadata, key, AES256_KEYLEN);
		if(text_len < 0)
			return -1;
	}

	encrypt_len = encrypt_symmetric_key(uid, key, text_len,
			(char *)uk.encrypted_key, ENC_KEYLEN);
	if(encrypt_len < 0)
		return -1;

	ret = write_new_user_key(metadata, &uk);
	return ret;
}

void mpv_aes_init(unsigned char *key, unsigned char *iv, evp_cipher_ctx *e_ctx,
		evp_cipher_ctx *d_ctx)
{
	if (e_ctx) {
		evp_cipher_ctx_init(e_ctx);
		evp_encryptinit_ex(e_ctx, evp_aes_256_cbc(), null, key, iv);
	}
	if (d_ctx) {
		evp_cipher_ctx_init(d_ctx);
		evp_decryptinit_ex(d_ctx, evp_aes_256_cbc(), null, key, iv);
	}
}

unsigned char *mpv_aes_encrypt(evp_cipher_ctx *e, unsigned char *plaintext,
		int *len)
{
	int c_len = *len + aes_block_size, f_len = 0;
	unsigned char *ciphertext = malloc(c_len);

	evp_encryptinit_ex(e, null, null, null, null);
	evp_encryptupdate(e, ciphertext, &c_len, plaintext, *len);
	evp_encryptfinal_ex(e, ciphertext + c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

unsigned char *mpv_aes_decrypt(evp_cipher_ctx *d, unsigned char *ciphertext,
		int *len)
{
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = malloc(p_len + aes_block_size);

	evp_decryptinit_ex(d, null, null, null, null);
	evp_decryptupdate(d, plaintext, &p_len, ciphertext, *len);
	evp_decryptfinal_ex(d, plaintext + p_len, &f_len);

	*len = p_len + f_len;
	return plaintext;
}
