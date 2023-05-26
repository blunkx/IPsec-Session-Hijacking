#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ifaddrs.h>
#include <unistd.h>

#include "net.h"
#include "transport.h"
#include "esp.h"

uint16_t cal_ipv4_cksm(struct iphdr iphdr)
{
    // [TODO]: Finish IP checksum calculation
    uint8_t *hdr_head = (uint8_t *)&iphdr;
    u_int32_t sum = 0;
    for (int i = 0; i < sizeof(struct iphdr); i += 2)
    {
        u_int16_t temp;
        if (i != 10)
        {
            temp = (hdr_head[i] << 8u) & 0xff00;
            temp += (hdr_head[i + 1] & 0x00ff);
            sum += temp;
            if (sum & (0x10000))
            {
                sum &= 0x0000ffff;
                sum += 1;
            }
        }
    }
    u_int16_t result = ((~sum) & 0x0000ffff);
    return htons(result);
}

uint8_t *dissect_ip(Net *self, uint8_t *pkt, size_t pkt_len)
{
    // [TODO]: Collect information from pkt.
    // Return payload of network layer

    self->ip4hdr = *(struct iphdr *)pkt;
    // self->hdrlen(20) done in init, always the same
    self->plen = pkt_len - self->hdrlen;
    self->pro = self->ip4hdr.protocol;
    inet_ntop(AF_INET, &(self->ip4hdr.saddr), self->src_ip, INET_ADDRSTRLEN); // addr in hdr is big endian
    inet_ntop(AF_INET, &(self->ip4hdr.daddr), self->dst_ip, INET_ADDRSTRLEN); // local is liitle endian

    return pkt + self->hdrlen;
}

Net *fmt_net_rep(Net *self)
{
    // [TODO]: Fill up self->ip4hdr (prepare to send)
    self->ip4hdr.tot_len = ntohs(self->plen + sizeof(struct iphdr));
    self->ip4hdr.check = cal_ipv4_cksm(self->ip4hdr);
    return self;
}

void init_net(Net *self)
{
    if (!self)
    {
        fprintf(stderr, "Invalid arguments of %s.", __func__);
        exit(EXIT_FAILURE);
    }

    self->src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_src_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->x_dst_ip = (char *)malloc(INET_ADDRSTRLEN * sizeof(char));
    self->hdrlen = sizeof(struct iphdr);

    self->dissect = dissect_ip;
    self->fmt_rep = fmt_net_rep;
}
