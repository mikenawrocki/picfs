#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <libgen.h>
#include <limits.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <regex.h>

#include "uid_crypto.h"
#include "acl.h"
#include "crypto.h"
#include "metadata.h"
#include "uthash/uthash.h"
#include "exif.h"

typedef struct table_entry {
	int fd; /*key for hash table*/
	char *decrypt_buf;
	int len;
	UT_hash_handle hh;
} table_entry;

static table_entry *fd_to_decrypted = NULL;
char *backing_dir;

static inline void make_path(char fpath[PATH_MAX], const char *path)
{
	strncpy(fpath, backing_dir, PATH_MAX);
	strncat(fpath, path, PATH_MAX);
}

static int mpv_getattr(const char *path, struct stat *stbuf)
{
	int ret = 0;
	char fpath[PATH_MAX];
	make_path(fpath, path);

	ret = lstat(fpath, stbuf);
	if(ret < 0)
		ret = -errno;

	return ret;
}

static int mpv_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		off_t offset, struct fuse_file_info *fi)
{
	DIR *dirp;
	struct dirent *ent;
	static regex_t *restricted_paths = NULL;
	fprintf(stderr, "%s\n", path);
	if(!restricted_paths) {
		restricted_paths = malloc(sizeof(regex_t));
		regcomp(restricted_paths, "(\\.meta$)", REG_EXTENDED);
	}

	dirp = (DIR *)fi->fh;

	if(!(ent = readdir(dirp))) {
		return -EINVAL;
	}

	do {
		if(regexec(restricted_paths, ent->d_name, 0, NULL, 0)) {
			if(filler(buf, ent->d_name, NULL, 0)) {
				return -ENOMEM;
			}
		}
	} while((ent = readdir(dirp)));

	return 0;
}

static int mpv_opendir(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;
	DIR *dp;
	char fpath[PATH_MAX];

	make_path(fpath, path);

	dp = opendir(fpath);
	if(dp == NULL)
		ret = -errno;
	fi->fh = (intptr_t)dp;
	return ret;
}

static int mpv_open(const char *path, struct fuse_file_info *fi)
{
	int fd, olen, len;
	char fpath[PATH_MAX], *decrypt_buf;
	unsigned char *mapped_file;
	unsigned char key[AES256_KEYLEN], iv[IVLEN];

	make_path(fpath, path);
	if((fd = open(fpath, fi->flags)) < 0) {
		printf("ERROR: %s\n", fpath);
		return -errno;
	}

	olen = len = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	mapped_file = (unsigned char*)mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0);
	if (mapped_file == MAP_FAILED) {
		return -errno;
	}

	strncat(fpath, ".meta", PATH_MAX);
	FILE *metadata = fopen(fpath, "r");
	if(!metadata) { //File without associated metadata.
		return -EACCES;
	}

	decrypt_metadata(metadata, key, iv, AES256_KEYLEN, IVLEN);
	fclose(metadata);

	// decrypt buffer
	EVP_CIPHER_CTX d_ctx;
	mpv_aes_init(key, iv, NULL, &d_ctx);
	decrypt_buf = (char *)mpv_aes_decrypt(&d_ctx, mapped_file, &len);
	EVP_CIPHER_CTX_cleanup(&d_ctx);

	munmap(mapped_file, olen);

	//printf("decrypt_buff: %s\n", decrypt_buf);

	table_entry *e = malloc(sizeof(table_entry));
	e->fd = fd;
	e->len = len;
	e->decrypt_buf= decrypt_buf;
	HASH_ADD_INT(fd_to_decrypted, fd, e);

	fi->fh = fd;
	return 0;
}

static int mpv_read(const char *path, char *buf, size_t size, off_t offset,
		struct fuse_file_info *fi)
{
	table_entry *e;
	HASH_FIND_INT(fd_to_decrypted, &fi->fh, e);
	if(!e) return -errno;

	if (size + offset > e->len) {
		printf("Read was %zu shrink to %ld\n", size, e->len - offset);
		size = e->len - offset;
	}

	memcpy(buf, e->decrypt_buf + offset, size);
	return size;
}

static int mpv_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	table_entry *e;
	HASH_FIND_INT(fd_to_decrypted, &fi->fh, e);
	if(!e) return -errno;

	if(size + offset > e->len) {
		printf("Resizing from: %d to %lu bytes\n", e->len, size + offset);
		e->decrypt_buf = realloc(e->decrypt_buf, size+offset);
		e->len = size + offset;
	}

	memcpy(e->decrypt_buf + offset, buf, size);
	return size;
}

static int mpv_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd, ret = 0;
	char fpath[PATH_MAX], mpath[PATH_MAX];
	unsigned char *key = malloc(AES256_KEYLEN), *iv = malloc(IVLEN);

	make_path(fpath, path);

	if((fd = creat(fpath, mode)) < 0) {
		ret = -errno;
	}
	uid_t uid = getuid();

	RAND_bytes(key, AES256_KEYLEN);
	RAND_bytes(iv, IVLEN);

	strncpy(mpath, fpath, PATH_MAX);
	strncat(mpath, ".meta", PATH_MAX);

	create_metadata_file(mpath, iv);
	FILE *metadata = fopen(mpath, "r+");
	add_user_key(metadata, uid, key);
	fclose(metadata);

	table_entry *e = malloc(sizeof(table_entry));
	e->fd = fd;
	e->len = 0;
	e->decrypt_buf = NULL;
	HASH_ADD_INT(fd_to_decrypted, fd, e);
	fi->fh = fd;

	//TODO Is it safe to free these now are they written to .meta file
	free(key);
	free(iv);

	return ret;

}

static int mpv_utimens(const char *path, const struct timespec tv[2])
{
	int ret = 0;
	char fpath[PATH_MAX];

	make_path(fpath, path);

	if((ret = utimensat(AT_FDCWD, fpath, tv, 0)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_access(const char *path, int mode)
{
	int ret = 0;
	char fpath[PATH_MAX];
	make_path(fpath, path);
	if((ret = access(fpath, mode)) < 0 ) {
		ret = -errno;
	}
	else if(strstr(path,"keys")) {
		ret = -ENOENT;
	}
	return ret;
}

static int mpv_chmod(const char *path, mode_t mode)
{
	int ret = 0;
	char fpath[PATH_MAX];
	make_path(fpath, path);
	if((ret = chmod(fpath, mode)) < 0) {
		ret = -errno;
	}
	return ret;
}

static int mpv_chown(const char *path, uid_t owner, gid_t group)
{
	int ret = 0;
	char fpath[PATH_MAX];
	make_path(fpath, path);
	if((ret = chown(fpath, owner, group)) < 0) {
		ret = -errno;
	}
	return ret;
}

static int mpv_fallocate(const char *path, int mode, off_t offset, off_t len,
		struct fuse_file_info *fi)
{
	int ret = 0;

	if((ret = fallocate(fi->fh, mode, offset, len)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_fgetattr(const char *path, struct stat *statbuf,
		struct fuse_file_info *fi)
{
	int ret = 0;

	if((ret = fstat(fi->fh, statbuf)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_flock(const char *path, struct fuse_file_info *fi, int op)
{
	int ret = 0;

	if((ret = flock(fi->fh, op)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_fsync(const char *path, int datasync, struct fuse_file_info *fi)
{
	int ret = 0;

	ret = (datasync) ? fdatasync(fi->fh) : fsync(fi->fh);
	if(ret < 0)
		ret = -errno;

	return ret;
}

static int mpv_ftruncate(const char *path, off_t offset,
		struct fuse_file_info *fi)
{
	table_entry *e;
	HASH_FIND_INT(fd_to_decrypted, &fi->fh, e);
	if(!e) return -errno;

	if(e->len > offset) {
		e->len = offset;
	}
	else if(e->len < offset) {
		e->decrypt_buf = realloc(e->decrypt_buf, offset);
		memset(e->decrypt_buf + e->len, 0, offset - e->len);
		e->len = offset;
	}
	return 0;
}

static int mpv_getxattr(const char *path, const char *attr_name, char *val,
		size_t size)
{
	int ret = 0;
	char fpath[PATH_MAX];

	make_path(fpath, path);

	if((ret = lgetxattr(fpath, attr_name, val, size)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_listxattr(const char *path, char *list, size_t size)
{
	int ret = 0;
	char fpath[PATH_MAX];

	make_path(fpath, path);

	if((ret = llistxattr(fpath, list, size)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_link(const char *src_path, const char *dst_path)
{
	int ret = 0;
	char fsrc_path[PATH_MAX];
	char fdst_path[PATH_MAX];

	make_path(fsrc_path, src_path);
	make_path(fdst_path, dst_path);

	if((ret = link(fsrc_path, fdst_path)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_mkdir(const char *path, mode_t mode)
{
	int ret = 0;
	char fpath[PATH_MAX];

	make_path(fpath, path);

	if((ret = mkdir(fpath, mode)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_readlink(const char *path, char *buf, size_t bufsiz)
{
	int ret = 0;
	char fpath[PATH_MAX];

	make_path(fpath, path);

	if((ret = readlink(fpath, buf, bufsiz)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_release(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;
	unsigned char key[AES256_KEYLEN], iv[IVLEN];
	unsigned char *encrypt_buf;
	char mpath[PATH_MAX];
	char fpath[PATH_MAX];
	static regex_t *sorted_path = NULL;
	if(!sorted_path) {
		sorted_path = malloc(sizeof(regex_t));
		regcomp(sorted_path, "\\/sorted/[^\\/]+$", REG_EXTENDED);
	}

	table_entry *e;
	HASH_FIND_INT(fd_to_decrypted, &fi->fh, e);
	if(!e) fprintf(stderr, "Hash Key not found!\n");

	make_path(fpath, path);
	strncpy(mpath, fpath, PATH_MAX);
	strncat(mpath, ".meta", PATH_MAX);
	FILE *metadata = fopen(mpath, "r");
	decrypt_metadata(metadata, key, iv, AES256_KEYLEN, IVLEN);
	fclose(metadata);

	// Encrypt buffer
	printf("to encrypt: %s", e->decrypt_buf);
	EVP_CIPHER_CTX e_ctx;
	mpv_aes_init(key, iv, &e_ctx, NULL);
	encrypt_buf = mpv_aes_encrypt(&e_ctx, e->decrypt_buf, &e->len);
	EVP_CIPHER_CTX_cleanup(&e_ctx);


	// Write buff back to file
	ftruncate(fi->fh, 0);
	pwrite(fi->fh, encrypt_buf, e->len, 0);

	if((ret = close(fi->fh)) < 0) {
		ret = -errno;
	}
	else if(!regexec(sorted_path, path, 0, NULL, 0)) {
		char *date = exif_date(e->decrypt_buf, e->len);
		// Need to make copies, dirname() and basename() can modify
		// their arguments...
		char *fpath_copy = strndup(fpath, PATH_MAX);
		char *path_copy = strndup(path, PATH_MAX);

		char *fdirpath = dirname(fpath_copy);
		char *fname = basename(path_copy);
		char *newpath = NULL;
		if(!date) {
			newpath = malloc(PATH_MAX);
			strncpy(newpath, fdirpath, PATH_MAX);
			strncat(newpath, "/unknown/", PATH_MAX);
			mkdir(newpath, 0755);
		}
		else {
			newpath = make_date_path(fdirpath, date);
		}

		if(newpath) {
			strncat(newpath, fname, PATH_MAX);
			rename(fpath, newpath);
			strncat(newpath, ".meta", PATH_MAX);
			rename(mpath, newpath);
		}
		free(newpath);
		free(date);
		free(fpath_copy);
		free(path_copy);
	}

	// Clean up
	HASH_DEL(fd_to_decrypted, e);
	free(e->decrypt_buf);
	free(e);
	free(encrypt_buf);

	return ret;
}

static int mpv_releasedir(const char *path, struct fuse_file_info *fi)
{
	int ret = 0;

	if((ret = closedir((DIR *)fi->fh)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_removexattr(const char *path, const char *name)
{
	int ret = 0;
	char fpath[PATH_MAX];

	make_path(fpath, path);

	if((ret = removexattr(fpath, name)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_setxattr(const char *path, const char *name, const char *val,
		size_t size, int flags)
{
	int ret = 0;
	char fpath[PATH_MAX];
	char metadata_path[PATH_MAX];
	char key[32], iv[32];
	FILE *metadata;
	acl_t acl;
	acl_type_t type = ACL_TYPE_ACCESS;
	uid_t acl_users[25];
	int i, acl_ndx = 0;

	make_path(fpath, path);
	strncpy(metadata_path, fpath, PATH_MAX);
	strncat(metadata_path, ".meta", PATH_MAX);

	if((ret = setxattr(fpath, name, val, size, flags)) < 0) {
		return -errno;
	}

	if((ret = setxattr(metadata_path, name, val, size, flags)) < 0) {
		return -errno;
	}

	if(!strcmp(name, "system.posix_acl_access")) {
		acl = acl_get_file(fpath, type);
		if (acl == NULL)
			return -1;
		acl_ndx = get_acl_uids(acl, acl_users, 25);

		if (acl_free(acl) < 0)
			return -1;
	
		metadata = fopen(metadata_path, "r+");
		if(!metadata) {
			return -ENOENT;
		}
		if((decrypt_metadata(metadata, key, iv, 32, 32)) < 0) {
			fclose(metadata);
			return -EPERM;
		}

		fclose(metadata);
		create_metadata_file(metadata_path, iv);
		metadata = fopen(metadata_path, "r+");

		add_user_key(metadata, getuid(), key);
		for(i = 0; i < acl_ndx; i++) {
			add_user_key(metadata, acl_users[i], key);
		}
		fflush(metadata);
		fclose(metadata);
	}

	return 0;
}

static int mpv_rename(const char *oldpath, const char *newpath)
{
	int ret = 0;
	char f_oldpath[PATH_MAX], f_newpath[PATH_MAX];
	char m_oldpath[PATH_MAX], m_newpath[PATH_MAX];

	make_path(f_oldpath, oldpath);
	make_path(f_newpath, newpath);

	strncpy(m_oldpath, f_oldpath, PATH_MAX);
	strncpy(m_newpath, f_newpath, PATH_MAX);

	strncat(m_oldpath, ".meta", PATH_MAX);
	strncat(m_newpath, ".meta", PATH_MAX);

	if((ret = rename(f_oldpath, f_newpath)) < 0) {
		return -errno;
	}
	if((ret = rename(m_oldpath, m_newpath)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_symlink(const char *target, const char *linkpath)
{
	int ret = 0;
	char f_target[PATH_MAX];
	char f_linkpath[PATH_MAX];

	make_path(f_target, target);
	make_path(f_linkpath, linkpath);

	if((ret = symlink(f_target, f_linkpath)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_rmdir(const char *path)
{
	int ret = 0;
	char fpath[PATH_MAX];

	make_path(fpath, path);

	if((ret = rmdir(fpath)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_unlink(const char *path)
{
	int ret = 0;
	char fpath[PATH_MAX], mpath[PATH_MAX];

	make_path(fpath, path);

	strncpy(mpath, fpath, PATH_MAX);
	strncat(mpath, ".meta", PATH_MAX);

	if((ret = unlink(fpath)) < 0) {
		return -errno;
	}
	if((ret = unlink(mpath)) < 0) {
		ret = -errno;
	}

	return ret;
}

static int mpv_truncate(const char *path, off_t offset)
{
	struct fuse_file_info *fi = malloc(sizeof(struct fuse_file_info));

	mpv_open(path, fi);
	int ret = mpv_ftruncate(NULL, 0, fi);
	mpv_release(path, fi);

	free(fi);

	return ret;
}

//TODO prune hidden files with stat
static int mpv_statfs(const char *path, struct statvfs *statv)
{
	int ret = 0;
	char fpath[PATH_MAX];

	make_path(fpath, path);
	if((ret = statvfs(fpath, statv)) < 0) {
		ret = -errno;
	}

	return ret;
}

static struct fuse_operations mpv_oper = {
	.getattr	= mpv_getattr,
	.opendir	= mpv_opendir,
	.readdir	= mpv_readdir,
	.access		= mpv_access,
	.open		= mpv_open,					// Decrypts buff X
	.create		= mpv_create,				// create iv + key + metadata X
	.chmod		= mpv_chmod,
	.chown		= mpv_chown,
	.read		= mpv_read,					// Uses decrypted X
	.write		= mpv_write,				// Uses decrypted X
	.utimens	= mpv_utimens,
	.fallocate	= mpv_fallocate,
	.fsync		= mpv_fsync,				//TODO Encrypts buff
	.ftruncate	= mpv_ftruncate,			// truncates decrypted X
	.listxattr	= mpv_listxattr,
	.getxattr	= mpv_getxattr,
	.setxattr	= mpv_setxattr,
	.removexattr	= mpv_removexattr,
	.flock		= mpv_flock,
	.release	= mpv_release,				// Closes and encrypts X
	.releasedir	= mpv_releasedir,
	.fgetattr	= mpv_fgetattr,
	.mkdir		= mpv_mkdir,
	.rmdir		= mpv_rmdir,
	.statfs 	= mpv_statfs,
	.truncate	= mpv_truncate,				// open, ftruncate, close X
	.rename		= mpv_rename,				// need to rename related metadata X
	.link		= mpv_link,
	.symlink	= mpv_symlink,
	.readlink	= mpv_readlink,
	.unlink		= mpv_unlink,				// Delete file + metadata X
};

int main(int argc, char *argv[])
{
	backing_dir = realpath(argv[argc-2], NULL);
	argv[argc-2] = argv[argc-1];
	argv[argc-1] = NULL;
	argc--;

	keypair = get_uid_rsa();
	if(keypair)
		return fuse_main(argc, argv, &mpv_oper, NULL);
	else
		exit(1);
}
