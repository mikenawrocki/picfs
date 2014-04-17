#include "uid_crypto.h"

RSA* create_key(char* path, uid_t uid, int mode)
{
	//creating the private key
	char key_path[80];
	strcpy(key_path, path);

	if(mode == PRIVATE)
		strcat(key_path, "/private");
	else if(mode == PUBLIC)
		strcat(key_path, "/public");
	else
	{
		fprintf(stderr, "Undefined mode\n");
		return NULL;
	}

	//generating the RSA 
	int num = 2048; // less than 1024 is considered not secure
	unsigned long e = 3; // exponent: odd number typically 3, 17, 65537 
	RSA* rsa_key = RSA_generate_key(num, e, NULL, NULL);

	if(!rsa_key)
	{	
		RSA_free(rsa_key);
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	FILE* file = fopen(key_path, "w+");
	int successful = 0;
	if(mode == PRIVATE)
	{
		const EVP_CIPHER* cipher = EVP_aes_256_cbc();
		successful = PEM_write_RSAPrivateKey(file,rsa_key,cipher,NULL,0,NULL,NULL);
	} else if(mode == PUBLIC)
	{
		successful = PEM_write_RSA_PUBKEY(file,rsa_key);
	}
	
	fclose(file);
	
	if(!successful)
	{
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	return rsa_key;
}

RSA* new_user(char* path, uid_t uid)
{
	if(create_key(path, uid, PUBLIC))
		return create_key(path, uid, PRIVATE);
	return NULL;
}

RSA* existing_user(char* path, uid_t uid)
{
	char key_path[80];
	strcpy(key_path, path);
	strcat(key_path, "/private");
	FILE* file = fopen(key_path, "r+");
	if(file)
	{
		RSA* rsa_key =  PEM_read_RSAPrivateKey(file,NULL,NULL,NULL);
		fclose(file);
		if(rsa_key){
			return rsa_key;
		}
		RSA_free(rsa_key);
	}
	fprintf(stderr, "Couldn't read the key\n");
	return NULL;
}

RSA* get_uid_rsa()
{
	uid_t current_uid = getuid();
	char path[80];
	strcpy(path, "keys/%d");
	sprintf(path, path, current_uid);
	
	int err = mkdir(path, S_IRWXU);
	printf("%s\n", path);
	printf("error info: %d\n", err);
	if(err == -1)
		return existing_user(path, current_uid);
	else if(err == 0)
		return new_user(path, current_uid);
	else 
		fprintf(stderr, "Unexpected error");
	return NULL;
}


void init_openssl()
{
    if(SSL_library_init())
    {
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        RAND_load_file("/dev/urandom", 1024);
    }
    else
        exit(1);
}

int main(int argc, char const *argv[])
{	
	RSA* rsa_key;
	init_openssl();
	rsa_key = get_uid_rsa();
	if(rsa_key)
		printf("It works!\n");

	return 0;
}