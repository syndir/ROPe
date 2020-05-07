CC := gcc
CFLAGS := -g -fno-stack-protector 

.PHONY: clean all

all: vuln vuln2 notvuln
	sudo sh -c "/bin/echo 0 > /proc/sys/kernel/randomize_va_space"

vuln: vuln.o
	$(CC) $(CFLAGS) vuln.c -o vuln
	sudo chown root:root vuln
	sudo chmod +s vuln

vuln2: vuln2.o
	$(CC) $(CFLAGS) vuln2.c -o vuln2
	sudo chown root:root vuln2
	sudo chmod +s vuln2

notvuln: notvuln.o
	$(CC) $(CFLAGS) notvuln.c -o notvuln
	sudo chown root:root notvuln
	sudo chmod +s notvuln

clean:
	sudo rm -rf vuln vuln.o vuln2 vuln2.o notvuln.o notvuln *.ROPe
