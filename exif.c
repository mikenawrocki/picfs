#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <regex.h>
#include <libexif/exif-data.h>
#include <libexif/exif-loader.h>
#include <libexif/exif-log.h>
#include <libexif/exif-mem.h>
#include <libexif/exif-ifd.h>
#include <libexif/exif-data-type.h>

static inline void _add_path_component(char *base, char *to_append)
{
	strncat(base, "/", PATH_MAX);
	strncat(base, to_append, PATH_MAX);
	strncat(base, "/", PATH_MAX);
}

char *make_date_path(char *base, char *date)
{
	char *new_path = malloc(PATH_MAX);
	char *year, *month, *day;

	year = strtok(date, ":");
	month = strtok(NULL, ":");
	day = strtok(NULL, ":");

	strncpy(new_path, base, PATH_MAX);
	_add_path_component(new_path, year);
	mkdir(new_path, 0755);
	_add_path_component(new_path, month);
	mkdir(new_path, 0755);
	_add_path_component(new_path, day);
	mkdir(new_path, 0755);
	return new_path;
}

char *exif_date(char *img_data, size_t len)
{
	static regex_t *regex = NULL;
	char *ret = NULL;
	if(!regex) {
		regex = malloc(sizeof(regex_t));
		regcomp(regex, "^[[:digit:]]{4}:[[:digit:]]{2}:[[:digit:]]{2}",
			REG_EXTENDED);
	}

	ExifLoader *loader = exif_loader_new();
	exif_loader_write(loader, img_data, len);
	ExifData *data = exif_loader_get_data(loader);
	exif_loader_unref(loader);
	ExifEntry *e = NULL;


	if(!data) {
		fprintf(stderr, "NO EXIF DATA FOUND!\n");
		ret = NULL;
		goto cleanup;
	}

	e = exif_data_get_entry(data, EXIF_TAG_DATE_TIME);
	if(!e || e->format != EXIF_FORMAT_ASCII) {
		fprintf(stderr, "NO DATE FOUND.\n");
		ret = NULL;
		goto cleanup;
	}

	char *date_str = e->data;
	if(regexec(regex, date_str, 0, NULL, 0) == REG_NOMATCH) {
		fprintf(stderr, "INVALID DATE FORMAT.\n");
		ret = NULL;
		goto cleanup;
	}

	ret = malloc(16);
	date_str = strtok(date_str, " ");
	strncpy(ret, date_str, 16);

cleanup:
	exif_data_unref(data);
	return ret;
}
