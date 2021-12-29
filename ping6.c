/* This code is copied from https://github.com/iputils/iputils/blob/master/ping.c
 * and ping_common.c
 * omitting lots of pieces with bits copied from both files
 * The aim is to understand how to write a basic ping program using IPPROTO_ICMP
 * as implemented in https://lwn.net/Articles/443051/
 *
 * ping6.c IPv6 ping
 * 2021.12.29. Chul-Woong Yang <cwyang@gmail.com>
 */

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netdb.h>
#include <stdlib.h>

#if BYTE_ORDER == LITTLE_ENDIAN
# define ODDBYTE(v)	(v)
#elif BYTE_ORDER == BIG_ENDIAN
# define ODDBYTE(v)	((unsigned short)(v) << 8)
#else
# define ODDBYTE(v)	htons((unsigned short)(v) << 8)
#endif

char * pr_addr(void *sa, socklen_t salen)
{
    static char buffer[4096] = "";
    static struct sockaddr_storage last_sa = { 0 };
    static socklen_t last_salen = 0;
    char address[128];

    if (salen == last_salen && !memcmp(sa, &last_sa, salen))
        return buffer;

    memcpy(&last_sa, sa, (last_salen = salen));
    getnameinfo(sa, salen, address, sizeof address, NULL, 0, NI_NUMERICHOST);
    snprintf(buffer, sizeof buffer, "%s", address);

    return(buffer);
}


unsigned short
in_cksum(const unsigned short *addr, register int len, unsigned short csum)
{
    register int nleft = len;
    const unsigned short *w = addr;
    register unsigned short answer;
    register int sum = csum;

    /*
     *  Our algorithm is simple, using a 32 bit accumulator (sum),
     *  we add sequential 16 bit words to it, and at the end, fold
     *  back all the carry bits from the top 16 bits into the lower
     *  16 bits.
     */
    while (nleft > 1)  {
        sum += *w++;
        nleft -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nleft == 1)
        sum += ODDBYTE(*(unsigned char *)w); /* le16toh() may be unavailable on old systems */

    /*
     * add back carry outs from top 16 bits to low 16 bits
     */
    sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
    sum += (sum >> 16);			/* add carry */
    answer = ~sum;				/* truncate to 16 bits */
    return (answer);
}

/*
 * pinger --
 *      Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is a random number,
 * and the sequence number is an ascending integer.  The first several bytes
 * of the data portion are used to hold a UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 */
int build_echo(uint8_t *_icmph, unsigned packet_size __attribute__((__unused__)))
{
    struct icmp6_hdr *icmph;
    int cc;

    icmph = (struct icmp6_hdr *)_icmph;
    icmph->icmp6_type = ICMP6_ECHO_REQUEST;
    icmph->icmp6_code = 0;
    icmph->icmp6_cksum = 0;
    icmph->icmp6_seq = htons(1);
    icmph->icmp6_id = 0xdead;

    cc = 56 + 8;
    /* skips ICMP portion */
    return cc;
}


#define getaddrinfo_flags (AI_CANONNAME)
#define getnameinfo_flags 0

/* argv[1] = ipv6addr, argv[2] = device */

int main(int argc, char **argv) {
    int sock, alen = sizeof(struct sockaddr_in6);
    struct sockaddr_in6 source = { .sin6_family = AF_INET6 };
    struct sockaddr_in6 dst;
    const char *device = argv[2];

    /* We first try to make a UDP connection
     * on port 1025 to the destination host
     * so that we can set the source IP correctly
     */
    memset((char *)&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    {
        struct addrinfo hints = {
            .ai_family = AF_INET6,
            .ai_protocol = IPPROTO_UDP,
            .ai_socktype = SOCK_DGRAM,
            .ai_flags = getaddrinfo_flags
        };
        struct addrinfo *result, *ai;
        int ret_val = getaddrinfo(argv[1], NULL, &hints, &result);

        if (ret_val) {
            fprintf(stderr, "%s: %s", argv[1], gai_strerror(ret_val));
            exit(1);
        }
        for (ai = result; ai; ai = ai->ai_next) {
            if (ai->ai_family == AF_INET6) {
                memcpy(&dst, ai->ai_addr, sizeof(dst));
                fprintf(stdout, "pinging to [%s]\n",
                        pr_addr(&dst, sizeof(dst)));
                break;
            }
        }
        freeaddrinfo(result);
    }
    
    dst.sin6_port = htons(1025);
    // Create a socket
    sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (sock == -1) {
        perror("Error creating socket");
    }

    int probe_fd = -1;
    if (1) {// fill source
        probe_fd = socket(AF_INET6, SOCK_DGRAM, 0);
        if (probe_fd < 0) {
            fprintf(stderr, "socket");
            exit (1);
        }
        if (device) {
            if (setsockopt(probe_fd, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1) == -1) {
                fprintf(stderr, "setsockopt(SO_BINDTODEVICE) %s", device);
                exit(1);
            }
        }
        if (connect(probe_fd, (struct sockaddr *)&dst, sizeof(dst)) == -1) {
            if (errno == EHOSTUNREACH) {
                close(probe_fd);
                return -1;
            }
            fprintf(stderr, "connect");
            exit (1);
        }
    }

    if (getsockname(probe_fd >= 0 ? probe_fd : sock, (struct sockaddr*)&source, &alen) == -1) {
        perror("getsockname");
        exit(2);
    }
    source.sin6_port = 0;
    
    if (probe_fd >= 0)
        close(probe_fd);
    
    
    if (device) {
        if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, device, strlen(device) + 1) == -1) {
            fprintf(stderr, "setsockopt(SO_BINDTODEVICE) %s", device);
            exit(1);
        }
    }
    
    fprintf(stdout, "pinging from [%s]\n",
            pr_addr(&source, sizeof(source)));
    // Source IP address that's set
    //char *ip = inet_ntoa(source.sin_addr);
    //printf("%s\n", ip);
    
    /* Now we create the packet that we send down the wire
     * Since we use IPPROTO_ICMP, we just have to create the
     * ICMP packet
     */
    int datalen = 56;
    int MAXIPLEN = 60;
    int MAXICMPLEN = 76;
    unsigned char *packet;
    struct icmphdr *icp;
    int ntransmitted = 0;

    int packlen = datalen + MAXIPLEN + MAXICMPLEN;
    if (!(packet = (unsigned char *)malloc((unsigned int)packlen))) {
        fprintf(stderr, "ping: out of memory.\n");
        exit(2);
    }
    icp = (struct icmphdr *)packet;
    int cc = build_echo(packet, packlen);
    
    /* We are sending a ICMP_ECHO ICMP packet */
    /* We don't set the echo.id here since IPPROTO_ICMP does it for us
     * it sets it to the source port
     * pfh.icmph.un.echo.id = inet->inet_sport;
     */

    /* compute ICMP checksum here */
/*    int cc = datalen + 8;
      icp->checksum = in_cksum((unsigned short *)icp, cc, 0);
*/
    /* send the ICMP packet*/
    int i = sendto(sock, icp, cc, 0, (struct sockaddr*)&dst, sizeof(dst));
    printf("Sent %d bytes  cc=%d\n", i,cc);
    if (i < 0) {
        printf("errno: %d\n", errno);
    }
    

    /* We have sent the packet, time to attempt to read
     * the reply
     * */
    struct msghdr msg;
    int polling;
    char addrbuf[128];
    struct iovec iov;

    iov.iov_base = (char *) packet;
    iov.iov_len = packlen;

    memset(&msg, 0, sizeof(msg));

    /* check recvmsg() to understand the reasoning/meaning
     * for the different fields
     */
    msg.msg_name = addrbuf;
    msg.msg_namelen = sizeof(addrbuf);
    /* Learn more: 
     * https://www.safaribooksonline.com/library/view/linux-system-programming/9781449341527/ch04.html
     */
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    /* We do a blocking wait here */
    polling = MSG_WAITALL;
    /* check the man page for recvmsg to understand why we need
     * to pass msg here
     * TLDR: passing msg here allows us to check the source
     * address for the unconnected socket, sock
     */
    cc = recvmsg(sock, &msg, polling);
    if (cc  < 0 ){
        perror("Error in recvmsg");
        exit(1);
    }

    uint8_t *buf = msg.msg_iov->iov_base;
    struct cmsghdr *c;
    struct icmp6_hdr *icmph;
    int hops = -1;
    int wrong_source = 0;

    for (c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c)) {
        if (c->cmsg_level != IPPROTO_IPV6)
            continue;
        switch (c->cmsg_type) {
        case IPV6_HOPLIMIT:
            if (c->cmsg_len < CMSG_LEN(sizeof(int)))
                continue;
            memcpy(&hops, CMSG_DATA(c), sizeof(hops));
        }
    }
    /* Now the ICMP part */
    icmph = (struct icmp6_hdr *)buf;
    if (cc < 8) {
        fprintf(stderr, "packet too short: %d bytes", cc);
        return 1;
    }

    struct sockaddr_in6 *from = msg.msg_name;
    if (icmph->icmp6_type == ICMP6_ECHO_REPLY) {
        printf("%s\n", pr_addr(from, sizeof *from));
        printf("Reply of %d bytes received\n", cc);
        printf("icmp_code = %u\n", icmph->icmp6_code);
    } else {
        printf("Not a ICMP_ECHOREPLY\n");
        printf("Not a ICMP6_ECHO_REPLY: got type: %d", icmph->icmp6_type);
    }
    return 0;
}
