all: collide

CFLAGS := -O2 -g --std=gnu99 -Wall -D_GNU_SOURCE

clean:
	rm -f collide
