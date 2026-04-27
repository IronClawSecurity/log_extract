CC = gcc
CFLAGS = -Wall -Wextra -pedantic -std=c99 -D_DEFAULT_SOURCE -Iinclude
LDFLAGS =

# Common sources (compiled on all platforms)
SRC_COMMON = src/main.c src/cli.c src/filter.c src/collector.c \
             src/collect_auth.c src/collect_applog.c src/collect_netlog.c \
             src/collect_filemon.c src/hash.c src/util.c

# Platform-specific sources
ifeq ($(OS),Windows_NT)
  SRC_PLAT = src/platform_win32.c src/collect_eventlog.c src/archive_win32.c
  LDFLAGS += -lwevtapi -lshlwapi -ladvapi32
  TARGET = log_extract.exe
else
  SRC_PLAT = src/platform_linux.c src/collect_syslog.c src/archive_linux.c
  TARGET = log_extract
endif

SRC = $(SRC_COMMON) $(SRC_PLAT)
OBJ = $(SRC:src/%.c=build/%.o)

.PHONY: all clean

all: build $(TARGET)

build:
	mkdir -p build

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

build/%.o: src/%.c | build
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -rf build $(TARGET) log_extract log_extract.exe
