CC  	= gcc
CFLAGS  = -Wall -g -std=gnu99
LDFLAGS = -lnfc -lfreefare -lcurl -lc
BIN 	= airlock-provisioner

.PHONY: all
all: build/airlock-reader build/airlock-provisioner

build/airlock-reader: build/read_main.o build/util.o
	$(CC) $(LDFLAGS) $^ -o $@

build/airlock-provisioner: build/provision.o build/provision_main.o
	$(CC) $(LDFLAGS) $^ -o $@

build/%.o: src/%.c
	$(CC) -c $(CFLAGS) $< -o $@

clean:
	rm -rf build/*
