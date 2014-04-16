#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <fuse.h>
#include <limits.h>
#include <openssl/rand.h>
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

#include "crypto.h"
#include "metadata.h"
#include "uthash/uthash.h"

typedef struct table_entry {
	int fd; /*key for hash table*/
	char *decrypt_buf;
	int len;
	UT_hash_handle hh;
} table_entry;

static table_entry *fd_to_decrypted = NULL;
static char *backing_dir;

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

	dirp = (DIR *)fi->fh;

	if(!(ent = readdir(dirp))) {
		return -EINVAL;
	}

	do {
		if(filler(buf, ent->d_name, NULL, 0)) {
			return -ENOMEM;
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
	unsigned char *key = malloc(AES256_KEYLEN), *iv = malloc(IVLEN);

	make_path(fpath, path);
	if((fd = open(fpath, fi->flags)) < 0) {
		return -errno;
	}

	olen = len = lseek(fd, 0, SEEK_END);
	lseek(fd, 0, SEEK_SET);

	mapped_file = (unsigned char*)mmap(NULL, len, PROT_READ, MAP_FILE, fd, 0);

	strncat(fpath, ".meta", PATH_MAX);
	FILE *metadata = fopen(fpath, "r");
	decrypt_metadata(metadata, key, iv, AES256_KEYLEN, IVLEN);
	fclose(metadata);

	// decrypt buffer
	EVP_CIPHER_CTX d_ctx;
	mpv_aes_init(key, iv, NULL, &d_ctx);
	decrypt_buf = (char *)mpv_aes_decrypt(&d_ctx, mapped_file, &len);
	EVP_CIPHER_CTX_cleanup(&d_ctx);
	free(key);
	free(iv);

	munmap(mapped_file, olen);


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

	memcpy(buf, e->decrypt_buf + offset, size);
	return size;
}

static int mpv_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	table_entry *e;
	HASH_FIND_INT(fd_to_decrypted, &fi->fh, e);
	if(!e) return -errno;

	memcpy(e->decrypt_buf + offset, buf, size);
	return size;
}

static int mpv_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	int fd;
	char fpath[PATH_MAX], mpath[PATH_MAX];
	unsigned char *key = malloc(AES256_KEYLEN), *iv = malloc(IVLEN);

	make_path(fpath, path);

	if((fd = creat(fpath, mode)) < 0) {
		return -errno;
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

	close(fd);
	//TODO Is it safe to free these now are they written to .meta file
	free(key);
	free(iv);

	return mpv_open(fpath, fi);

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
	if((ret = access(fpath, mode)) < 0) {
		ret = -errno;
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
		realloc(e->decrypt_buf, e->len + offset);
		memset(e->decrypt_buf + e->len, 0, offset);
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
	unsigned char *key = malloc(AES256_KEYLEN), *iv = malloc(IVLEN);
	unsigned char *encrypt_buf;

	if((ret = close(fi->fh)) < 0) {
		ret = -errno;
	}

	table_entry *e;
	HASH_FIND_INT(fd_to_decrypted, &fi->fh, e);
	if(!e) fprintf(stderr, "Hash Key not found!\n");

	strncat(fpath, ".meta", PATH_MAX);
	FILE *metadata = fopen(fpath, "r");
	decrypt_metadata(metadata, key, iv, AES256_KEYLEN, IVLEN);
	fclose(metadata);

	// Encrypt buffer
	EVP_CIPHER_CTX e_ctx;
	mpv_aes_init(key, iv, &e_ctx, NULL);
	encrypt_buf = mpv_aes_encrypt(&e_ctx, e->decrypt_buf, &e->len);
	EVP_CIPHER_CTX_cleanup(&e_ctx);
	free(key);
	free(iv);


	// Write buff back to file
	ftruncate(fi->fh, 0);
	pwrite(fi->fh, encrypt_buf, e->len, 0);

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

	make_path(fpath, path);

	if((ret = setxattr(fpath, name, val, size, flags)) < 0) {
		ret = -errno;
	}

	return ret;
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
	strncat(m_oldpath, ".meta", PATH_MAX);

	if((ret = rename(f_oldpath, f_newpath)) < 0) {
		ret = -errno;
	}
	if((ret = rename(m_oldpath, m_newpath)) < 0) {
		if (ret >= 0)
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
		ret = -errno;
	}
	if((ret = unlink(mpath)) < 0) {
		if(ret >= 0)
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

	return fuse_main(argc, argv, &mpv_oper, NULL);
}
