all: collide

CFLAGS := -Os -g --std=gnu99 -Wall -D_GNU_SOURCE

clean:
	rm -f collide

check: collide
	# only two rdpmc insns, and 4 cpuid insns
	objdump -d collide | grep -c rdpmc | grep -q "^2$$"
	objdump -d collide | grep -c cpuid | grep -q "^4$$"
