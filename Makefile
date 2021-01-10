CC=gcc
CFLAGS= -Wall -Werror
OUT = tunproxy

SOURCE_FILES = src/main.c \
	src/tuntap/tuntap.c \

.PHONY: all
all: build

.PHONY: build
build:
	$(CC) $(CFLAGS) $(SOURCE_FILES) -Isrc/tuntap -Isrc/util -o $(OUT)

.PHONY: clean
clean:
	rm tunproxy
