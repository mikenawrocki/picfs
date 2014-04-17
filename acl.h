#ifndef ACL_H
#define ACL_H

#include <acl/libacl.h>
#include <sys/acl.h>
int get_acl_uids(acl_t acl, uid_t *uid_arr, int max_elems);

#endif 
