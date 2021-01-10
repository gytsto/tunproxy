CC=gcc
CFLAGS= -Wall -Werror
OUT = tunproxy

SOURCE_FILES = src/main.c \
	src/tuntap/tuntap.c \
	src/signal_handler/signal_handler.c \

.PHONY: all
all: build

.PHONY: build
build:
	$(CC) $(CFLAGS) $(SOURCE_FILES) -Isrc/tuntap -Isrc/util -Isrc/signal_handler -o $(OUT)

.PHONY: clean
clean:
	rm tunproxy
