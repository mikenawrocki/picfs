#ifndef EXIF_H
#define EXIF_H

char *make_date_path(char *base, char *date);
char *exif_date(char *img_data, size_t len);

#endif
