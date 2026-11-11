CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra -pthread
LDLIBS ?= -lncurses -pthread
ROOT := ../..
OUT ?= build/$(shell uname -m)/catscan
SOURCES := $(ROOT)/catscan.c $(ROOT)/hardware.c $(ROOT)/vm_ascii_map.c $(ROOT)/thread_ascii_map.c
PREFIX ?= /usr/local
DESTDIR ?=

.PHONY: all install uninstall clean
all: $(OUT)

$(OUT): $(SOURCES) $(ROOT)/netinspect.c $(ROOT)/hardware.h $(ROOT)/vm_ascii_map.h $(ROOT)/thread_ascii_map.h
	mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -o $@ $(SOURCES) $(LDLIBS)

install: $(OUT)
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(OUT) $(DESTDIR)$(PREFIX)/bin/catscan

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/catscan

clean:
	rm -rf build
