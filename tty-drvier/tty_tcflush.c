#include <stdio.h>                                                                                                 
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>



void main()
{
	int fd = 0;
	fd = open("/dev/ttyz1", O_RDWR);
	if (fd < 0)
		printf("open tty device fail, ret:%d\n", fd);

	tcflush(fd, TCIFLUSH);

	close(fd);

}
