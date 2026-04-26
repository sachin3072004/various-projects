/*
 * Simple TCP echo server.
 *
 * Build: cc -O2 -Wall -o server server.c
 * Run:   ./server 12345
 *
 * Listens on the given port, accepts one client at a time,
 * and echoes back whatever the client sends until the client closes.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "usage: %s <port>\n", argv[0]);
        return 1;
    }

    int port = atoi(argv[1]);
    if (port <= 0 || port > 65535) {
        fprintf(stderr, "invalid port: %s\n", argv[1]);
        return 1;
    }

    /* Don't crash if a client disconnects mid-send(). */
    signal(SIGPIPE, SIG_IGN);

    /* 1. Create a TCP socket. */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("socket");
        return 1;
    }

    /* 2. Allow quick restart after Ctrl-C (avoids "Address already in use"). */
    int yes = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    /* 3. Bind to 0.0.0.0:<port>  (all interfaces). */
    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_addr.s_addr = htonl(INADDR_ANY),
        .sin_port        = htons(port),
    };
    if (bind(lfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(lfd);
        return 1;
    }

    /* 4. Start listening, with a backlog of 16 pending connections. */
    if (listen(lfd, 16) < 0) {
        perror("listen");
        close(lfd);
        return 1;
    }

    printf("listening on 0.0.0.0:%d  (Ctrl-C to quit)\n", port);

    /* 5. Accept loop: handle one client at a time. */
    for (;;) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof(cli);

        int cfd = accept(lfd, (struct sockaddr *)&cli, &clen);
        if (cfd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            break;
        }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &cli.sin_addr, ip, sizeof(ip));
        printf("client connected: %s:%u\n", ip, ntohs(cli.sin_port));

        /* 6. Echo loop: read whatever the client sends, write it back. */
        char buf[4096];
        ssize_t n;
        while ((n = recv(cfd, buf, sizeof(buf), 0)) > 0) {
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = send(cfd, buf + off, n - off, 0);
                if (w < 0) {
                    perror("send");
                    break;
                }
                off += w;
            }
        }

        printf("client disconnected\n");
        close(cfd);
    }

    close(lfd);
    return 0;
}
