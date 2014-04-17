#include <acl/libacl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/acl.h>
#include <unistd.h>

static int compare_uids(const void *a, const void *b)
{
	return *(uid_t *)a - *(uid_t *)b;
}

int get_acl_uids(acl_t acl, uid_t *uid_arr, int max_elems)
{
	acl_entry_t entry;
	acl_tag_t tag;
	uid_t *uidp;

	int entry_id, acl_ndx = 0;
	for(entry_id = ACL_FIRST_ENTRY;
			acl_ndx < max_elems;
			entry_id = ACL_NEXT_ENTRY) {
		if(acl_get_entry(acl, entry_id, &entry) != 1)
			break;

		if(acl_get_tag_type(entry, &tag) < 0)
			return -1;

		if(tag == ACL_USER) {
			uidp = acl_get_qualifier(entry);
			uid_arr[acl_ndx++] = *uidp;
		}
	}

	qsort(uid_arr, acl_ndx, sizeof(uid_t), compare_uids);

	return acl_ndx;
}
