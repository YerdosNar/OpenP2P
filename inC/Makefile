CC      = gcc
CFLAGS  = -Wall -Wextra -Wpedantic -std=c11 -O2
LIBS    = -lsodium

SHARED_SRC  = src/crypto.c src/net.c
SHARED_OBJ  = $(SHARED_SRC:.c=.o)

PEER_SRC    = src/peer.c $(SHARED_SRC)
RENDEZVOUS_SRC = src/rendezvous.c src/room.c $(SHARED_SRC)

.PHONY: all clean

all: peer rendezvous

peer: $(PEER_SRC:.c=.o)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

rendezvous: $(RENDEZVOUS_SRC:.c=.o)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Header dependencies
peer.o:        src/peer.c        include/crypto.h include/net.h
crypto.o:      src/crypto.c      include/crypto.h include/net.h
net.o:         src/net.c         include/net.h
room.o:        src/room.c        include/room.h include/crypto.h
rendezvous.o:  src/rendezvous.c  include/crypto.h include/net.h include/room.h

clean:
	rm -f *.o peer rendezvous
