
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

int foo()
{
	mmap(NULL, 1, 7, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
	return 0;
}

int main(int argc, char *argv[])
{
	char buf[999];
	foo();
	gets(buf);
	return 0;
}
