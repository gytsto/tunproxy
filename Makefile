CC=gcc
CFLAGS= -Wall -Werror -pthread
OUT = tunproxy

SOURCE_FILES = src/main.c \
	src/tuntap/tuntap.c \
	src/signal_handler/signal_handler.c \
	src/socks5/socks5.c \

.PHONY: all
all: build

.PHONY: build
build:
	$(CC) $(CFLAGS) $(SOURCE_FILES) -Isrc/tuntap -Isrc/util -Isrc/signal_handler -Isrc/socks5 -o $(OUT)

.PHONY: clean
clean:
	rm tunproxy
