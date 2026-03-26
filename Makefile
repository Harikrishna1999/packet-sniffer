CC=gcc
CFLAGS=-Wall -Iinclude

SRC=src/main.c src/parser.c

all:
	$(CC) $(SRC) -o sniffer $(CFLAGS)

clean:
	rm -f sniffer
