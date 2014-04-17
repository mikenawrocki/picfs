#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <unistd.h>
#define _OPEN_SYS
int main(int argc, char const *argv[])
{
	// mkdir("hithere", S_IRWXU);
	unlink(("hithere/%s","things.txt"));
	unlink(("hithere/%s", "stuff.txt"));

	printf("Error code: %d\n",rmdir("hithere"));
	return 0;
}