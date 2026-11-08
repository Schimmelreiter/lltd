# lltd - Link Layer Topology Discovery responder
#
#   make                      build lltd
#   make test                 build and run the unit tests
#   make install DESTDIR=...  install to $(DESTDIR)$(PREFIX)/sbin
#
# Cross compiling: make CC=mipsel-openwrt-linux-musl-gcc

VERSION   ?= 1.0.0
PREFIX    ?= /usr
SBINDIR   ?= $(PREFIX)/sbin
MANDIR    ?= $(PREFIX)/share/man

CC        ?= cc
CFLAGS    ?= -O2
WARN      := -Wall -Wextra -Wno-unused-parameter
override CFLAGS += -std=gnu99 $(WARN) -DLLTD_VERSION_STRING='"$(VERSION)"'
LDFLAGS   ?=

CORE_SRC  := src/frame.c src/responder.c
DAEMON_SRC := $(CORE_SRC) src/sysinfo.c src/main.c src/icon_default.c

all: lltd

lltd: $(DAEMON_SRC) src/*.h
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) -o $@ $(DAEMON_SRC) $(LDLIBS)

tests/test_lltd: $(CORE_SRC) tests/test_lltd.c tests/pcap.c tests/pcap.h src/*.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -Isrc -o $@ $(CORE_SRC) tests/test_lltd.c tests/pcap.c

test: tests/test_lltd
	cd tests && ./test_lltd

install: lltd
	install -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(MANDIR)/man8
	install -m 0755 lltd $(DESTDIR)$(SBINDIR)/lltd
	install -m 0644 doc/lltd.8 $(DESTDIR)$(MANDIR)/man8/lltd.8

clean:
	rm -f lltd tests/test_lltd tests/out/*.pcap

.PHONY: all test install clean
