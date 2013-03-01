CC      = gcc
CFLAGS  = -O2 -D_GNU_SOURCE -Wall -g -D_FILE_OFFSET_BITS=64
LDFLAGS = -lpthread -lports -ldiskfs -lpager -lfshelp
SRC     = backing.c dir.c node.c pager.c anonfs.c
OBJ     = $(SRC:%.c=%.o)
TRANS   = anonfs

all: $(TRANS)

$(TRANS): $(OBJ)

clean: 
	rm -f $(TRANS) $(OBJ)
