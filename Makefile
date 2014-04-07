OBJS := main.o
CFLAGS := -std=gnu99 -Wall -c -g
CFLAGS += $(shell pkg-config --cflags fuse)
LDFLAGS := $(shell pkg-config --libs fuse)
DEFINES := -D FUSE_USE_VERSION=29 -D _GNU_SOURCE

all: mpv

%.o : %.c
	gcc ${CFLAGS} ${LDFLAGS} ${DEFINES} $^ -o $@

mpv: ${OBJS}
	gcc $^ ${LDFLAGS} -o $@

.PHONY: clean
clean:
	rm -f *.o mpv
