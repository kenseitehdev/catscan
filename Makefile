CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -pthread
LDLIBS ?= -lncurses -pthread
.PHONY: all clean test
all: catscan
catscan: catscan.c netinspect.c hardware.c hardware.h vm_ascii_map.c vm_ascii_map.h thread_ascii_map.c thread_ascii_map.h
	@platform_flags=; if [ "$$(uname -s)" = Darwin ]; then platform_flags='-framework IOKit -framework CoreFoundation'; fi; \
	$(CC) $(CFLAGS) -o $@ catscan.c hardware.c vm_ascii_map.c thread_ascii_map.c $(LDLIBS) $$platform_flags
vm-map-test: vm_ascii_test.c vm_ascii_map.c vm_ascii_map.h
	$(CC) $(CFLAGS) -o $@ vm_ascii_test.c vm_ascii_map.c
thread-map-test: thread_ascii_test.c thread_ascii_map.c thread_ascii_map.h
	$(CC) $(CFLAGS) -o $@ thread_ascii_test.c thread_ascii_map.c
test: catscan vm-map-test thread-map-test
	./vm-map-test
	./thread-map-test
	./catscan --self-test
clean:
	rm -f catscan vm-map-test thread-map-test
