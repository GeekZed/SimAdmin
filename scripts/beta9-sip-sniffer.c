#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

int main(void) {
    int fd = socket(AF_PACKET, SOCK_RAW, htons(0x86dd));
    if (fd < 0) { perror("socket"); return 1; }
    struct sockaddr_ll addr = {0};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(0x86dd);
    addr.sll_ifindex = (int)if_nametoindex("wwan1");
    if (!addr.sll_ifindex) { perror("if_nametoindex"); return 1; }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    unsigned char buf[16384];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            perror("recv");
            return 1;
        }
        for (ssize_t i = 0; i + 8 < n; ++i) {
            if (memcmp(buf + i, "REGISTER", 8) &&
                memcmp(buf + i, "MESSAGE ", 8) &&
                memcmp(buf + i, "SIP/2.0", 7)) {
                continue;
            }
            time_t now = time(NULL);
            printf("=== %ld offset=%ld len=%ld ===\n", (long)now, (long)i, (long)n);
            for (ssize_t j = i; j < n; ++j) {
                unsigned char c = buf[j];
                putchar((c >= 32 && c <= 126) || c == '\r' || c == '\n' ? c : '.');
            }
            printf("\n=== HEX ===\n");
            for (ssize_t j = i; j < n; ++j) printf("%02x", buf[j]);
            printf("\n");
            fflush(stdout);
            break;
        }
    }
}
