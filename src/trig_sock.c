#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void)
{
    errno = 0;
    int s = socket(30, SOCK_STREAM, 0);
    printf("socket(30) ret=%d errno=%d\n", s, errno);
    return 0;
}
