#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <unistd.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#define ICMP_HDR_SIZ 8
#define ICMP_BUF_SIZ 1000

#define ECHO_REPLY 0
#define ECHO_REQ 8

/*
 * Could have used the Linux ICMP structure of course.
 */
struct icmph
{
    uint8_t type;
    uint8_t code;
    uint16_t check;

    // Rest of header
    union
    {
        struct
        {
            uint16_t id;
            uint16_t seq;
        } echo;
    };
};

/*
 * Calculate an internet checksum.
 * The checksum is returned in network order.
 */
uint16_t icmp_checksum(uint16_t *buf, int siz);

/*
 * Usage : ping <host>
 * <host> can be an IPv4 adress or a host name.
 */
int main(int argc, char **argv)
{
    if (argc < 2)
    {
        fprintf(stderr, "%s : usage %s <host>\n", argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    // Resolve the host
    struct addrinfo *ll_addrinfo;
    if (getaddrinfo(argv[1], NULL, NULL, &ll_addrinfo) != 0)
    {
        fprintf(stderr, "%s : can't resolve host\n", argv[0]);
        return EXIT_FAILURE;
    }

    // Look for an IPv4 address in the list
    while (ll_addrinfo->ai_family != AF_INET)
        ll_addrinfo = ll_addrinfo->ai_next;

    if (ll_addrinfo == NULL)
    {
        fprintf(stderr, "%s : host doesn't have an IPv4 address\n", argv[0]);
        return EXIT_FAILURE;
    }

    struct sockaddr_in *sockaddr_in = (struct sockaddr_in *)(ll_addrinfo->ai_addr);
    printf("%s is reachable at %s\n\n", argv[1], inet_ntoa(sockaddr_in->sin_addr));

    // Create our raw IPv4 socket
    int sock_r = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sock_r == -1)
    {
        fprintf(stderr, "%s : can't create raw socket, %s\n", argv[0], strerror(errno));
        return EXIT_FAILURE;
    }

    // Create our ICMP echo request and echo reply
    char echo_req[ICMP_BUF_SIZ];
    memset(echo_req, 0x90, ICMP_BUF_SIZ);

    uint16_t echo_id = htons((uint16_t)getpid());

    struct icmph *icmph = (struct icmph *)echo_req;
    icmph->type = ECHO_REQ;
    icmph->code = 0;
    icmph->echo.id = echo_id;
    icmph->echo.seq = 0;

    // ICMP echo reply buffer
    char echo_reply[ICMP_BUF_SIZ];
    ssize_t rep_siz;

    // Stop this loop with with SIGINT
    while (1)
    {
        icmph = (struct icmph *)echo_req;
        icmph->echo.seq = htons(htons(icmph->echo.seq) + 1);
        icmph->check = 0;
        icmph->check = icmp_checksum((uint16_t *)echo_req, ICMP_BUF_SIZ / 2);

        if (sendto(sock_r, echo_req, ICMP_BUF_SIZ, 0, (struct sockaddr *)sockaddr_in, sizeof(struct sockaddr_in)) == -1)
        {
            fprintf(stderr, "%s : error while sending ICMP packet, %s\n", argv[0], strerror(errno));
            return EXIT_FAILURE;
        }

        printf("Echo request to %s, seq = %d\n", inet_ntoa(sockaddr_in->sin_addr), ntohs(icmph->echo.seq));

        // Loop until we receive the ICMP echo reply
        int stop = 0;
        while (!stop)
        {
            rep_siz = read(sock_r, echo_reply, ICMP_BUF_SIZ);
            struct iphdr *iphdr = (struct iphdr *)echo_reply;

            // That's an ICMP packet from our host
            if (iphdr->saddr == sockaddr_in->sin_addr.s_addr)
            {
                icmph = (struct icmph *)(echo_reply + iphdr->ihl * 4);

                // That's an ICMP echo reply to our echo request
                if (icmph->code == ECHO_REPLY && icmph->echo.id == echo_id)
                {
                    printf("Echo reply %s, seq = %d\n", inet_ntoa(sockaddr_in->sin_addr), ntohs(icmph->echo.seq));
                    stop = 1;
                }
            }

            // Read the rest of the data
            uint32_t pack_len = ntohs(iphdr->tot_len);
            while (rep_siz < pack_len)
            {
                rep_siz = read(sock_r, echo_reply, ICMP_BUF_SIZ);
                pack_len -= rep_siz;
            }
        }

        sleep(1);
        printf("\n");
    }

    close(sock_r);
    return EXIT_SUCCESS;
}

/*
 * Calculate an internet checksum.
 * The checksum is returned in network order.
 */
uint16_t icmp_checksum(uint16_t *buf, int siz)
{
    uint32_t sum;

    for (sum = 0; siz > 0; --siz)
        sum += ntohs(*(buf++));

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);

    return htons((uint16_t)~sum);
}
