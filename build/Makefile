all: logappend logread

CFLAGS=-g -Wall -O0
LIBS=-lcrypto

UNAME := $(shell uname)
ifeq ($(UNAME),Linux)
CFLAGS += -DLINUX -I/usr/local/ssl/include -L/usr/local/ssl/lib
endif

logappend: logappend.o
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

logread: logread.o
	$(CC) -o $@ $(CFLAGS) $^ $(LIBS)

logappend.o: logappend.c
	$(CC) -c -o $@ $(CFLAGS) $^

logread_skel.o: logread_skel.c
	$(CC) -c -o $@ $(CFLAGS) $^

clean:
	rm -f *.o logappend logread
