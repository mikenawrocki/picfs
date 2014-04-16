#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/*
 * Private (and optionally Public, though this is unnecessary) RSA key pair in
 * memory for the mounting user to decrypt files he has permissions for.
 */
extern RSA *keypair;

/*
 * Check to see if the provided UID already has an encrypted version of the
 * symmetric encryption key used to encrypt a particular file.
 */
int metadata_uid_exists(FILE *metadata, uid_t uid);

/*
 * Decrypt the symmetric file encryption key using the mounting user's keypair.
 * Returns the number of bytes that were decrypted (should always be 32 for
 * AES256)
 */
int decrypt_metadata_key(FILE *metadata, char *buf, size_t len);

/*
 * Encrypt a provided symmetric key using a target user's public RSA key.
 * key_len should always be 32 for AES256. The provided buffer should always be
 * 256 bytes. Afterwards, buf will be an OAEP padded, encrypted version of
 * the key, and should always be 256 bytes in length. The return should be this
 * 256 byte length.
 */
int encrypt_symmetric_key(uid_t target, const char *key, size_t key_len,
		char *buf, size_t buf_len);

/*
 * Write a new user_key structure to an existing metadata file. Increments
 * the metadata's n_user_keys count automatically.
 */
int write_new_user_key(FILE *metadata, struct user_key *uk);

/*
 * Create a new metadata file, with no user_keys, given an IV and a path. This
 * should be called before any of the other functions, which rely on a present
 * metadata file.
 */
int create_metadata_file(const char *path, const char *IV);

/*
 * Create an encrypted version of a file's symmetric key for a particular user.
 * If key is NULL, the metadata file is searched for the mounting user's UID,
 * and the associated encrypted symmetric key is decrypted, then re-encrypted
 * using the new uid's public RSA key.
 * If key is NOT NULL (e.g. when the metadata file is first being populated, on
 * file creation for example), the specified key is encrypted with the target
 * uid's public key and a corresponding entry is created in the metadata file.
 */
int add_user_key(FILE *metadata, uid_t uid, char *key);

#endif