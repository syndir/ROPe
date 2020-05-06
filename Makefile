CC := gcc
CFLAGS := -g -fno-stack-protector

.PHONY: clean all

all: vuln
	sudo sh -c "/bin/echo 0 > /proc/sys/kernel/randomize_va_space"

vuln: vuln.o
	$(CC) $(CFLAGS) vuln.c -o vuln
	sudo chown root:root vuln
	sudo chmod +s vuln

clean:
	sudo rm -rf vuln vuln.o
