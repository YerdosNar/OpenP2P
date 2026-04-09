# CC 	= gcc
# CFLAGS 	= -Wall -Wextra -Wpedantic -std=c11 -O2
# LIBS 	= -lsodium
#
# SHARED_SRC 	= src/crypto.c src/net.c
# SHARED_OBJ 	= $(SHARED_SRC:.c=.o)
#
# PEER_SRC 	= src/peer.c $(SHARED_SRC)
# RENDEZVOUS_SRC 	= src/rendezvous.c src/room.c $(SHARED_SRC)
#
# .PHONY: all clean
#
# all: peer rendezvous
#
# peer: $(PEER_SRC:.c=.o)
# 	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
#
# rendezvous: $(RENDEZVOUS_SRC:.c=.o)
# 	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)
#
# %.o: %.c
# 	$(CC) $(CFLAGS) -c -o $@ $<
#
# # Header dependencies
# peer.o:		src/peer.c 	 include/crypto.h include/net.h
# crypto.o:	src/crypto.c 	 include/crypto.h include/net.h
# net.o:		src/net.c 	 include/net.h
# room.o:		src/room.c 	 include/room.h include/crypto.h
# rendezvous.o: 	src/rendezvous.c include/room.h include/crypto.h include/net.h
#
# clean:
# 	rm -f *.o peer rendezvous

# Compiler and flags
CC = gcc
# The -Iinclude flag tells GCC to look in the 'include' folder for .h files
CFLAGS = -Wall -Wextra -g -O2 -Iinclude
LDFLAGS = -lsodium

# Directories
SRC_DIR = src
INC_DIR = include

# Header files (triggers recompile if modified)
DEPS = $(INC_DIR)/crypto.h $(INC_DIR)/net.h $(INC_DIR)/room.h

# Shared object files
SHARED_OBJ = $(SRC_DIR)/crypto.o $(SRC_DIR)/net.o $(SRC_DIR)/room.o

# The final executables to build
TARGETS = peer rendezvous

# Default rule
all: $(TARGETS)

# Generic rule for compiling .c files in the src/ directory into .o files
$(SRC_DIR)/%.o: $(SRC_DIR)/%.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

# Link the 'peer' executable
peer: $(SRC_DIR)/peer.o $(SHARED_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Link the 'rendezvous' executable
rendezvous: $(SRC_DIR)/rendezvous.o $(SHARED_OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Clean up built files
clean:
	rm -f $(SRC_DIR)/*.o $(TARGETS)

.PHONY: all clean
