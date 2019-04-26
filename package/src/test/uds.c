
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/un.h>

#define UNIX_SERVER_PATH  ("/var/run/nmap-scan.sock")
#define log_error(fmt, args...) printf("[%s-%d]: "fmt, __FUNCTION__, __LINE__, ##args)
#define log_debug(fmt, args...) printf("[%s-%d]: "fmt, __FUNCTION__, __LINE__, ##args)

int main(int argc, char *argv[])
{
    int ret;
    int sockfd;
    struct sockaddr_un addr;

    int wlen = 0;
    int rlen = 0;
    char rbuf[256] = {0};
    char wbuf[256] = {0};

    if(argc < 2)
    {
        log_error("param error!\n");
        return -1;
    }

    strncpy(wbuf, argv[1], sizeof(wbuf));

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, UNIX_SERVER_PATH);

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        log_error("socket: %s\n", strerror(errno));
        return -1;
    }

    ret = connect(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    if(ret < 0)
    {   
        close(sockfd);
        log_error("connect: %s\n", strerror(errno));
        return -1;
    }

    wlen = strlen(wbuf);
    ret = send(sockfd, wbuf, wlen, MSG_NOSIGNAL);
    if(ret < 0)
    {
        close(sockfd);
        log_error("send: %s\n", strerror(errno));
        return -1;
    }

    log_debug("wlen >> [%d]\n", wlen);
    log_debug("wbuf >> [%s]\n", wbuf);

    ret = recv(sockfd, rbuf, sizeof(rbuf), 0);
    if(ret < 0)
    {
        close(sockfd);
        log_error("recv: %s\n", strerror(errno));
        return -1;
    }

    rlen = ret;    
    log_debug("rlen << [%d]\n", rlen);
    log_debug("recv << [%s]\n", rbuf);
    close(sockfd);
    return 0;
}
