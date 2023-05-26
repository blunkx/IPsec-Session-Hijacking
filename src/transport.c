#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "net.h"
#include "transport.h"

uint32_t cksm_add(u_int32_t a, u_int32_t b)
{
    u_int32_t temp = a + b;
    if (temp & (0x10000))
    {
        temp &= 0x0000ffff;
        temp += 1;
    }
    return temp;
}

uint16_t cal_tcp_cksm(struct iphdr iphdr, struct tcphdr tcphdr, uint8_t *pl, int plen)
{
    // [TODO]: Finish TCP checksum calculation
    u_int32_t sum = 0;
    u_int32_t header_len = tcphdr.th_off * 4 + plen;
    uint8_t *hdr_head = (uint8_t *)&tcphdr;

    sum = cksm_add(sum, ((htonl(iphdr.saddr) & 0xffff0000) >> 16u));
    sum = cksm_add(sum, (htonl(iphdr.saddr) & 0x0000ffff));
    sum = cksm_add(sum, ((htonl(iphdr.daddr) & 0xffff0000) >> 16u));
    sum = cksm_add(sum, (htonl(iphdr.daddr) & 0x0000ffff));
    sum = cksm_add(sum, IPPROTO_TCP);
    sum = cksm_add(sum, header_len);

    for (int i = 0; i < tcphdr.th_off * 4; i += 2)
    {
        u_int16_t temp;
        if (i != 16)
        {
            temp = (hdr_head[i] << 8u) & 0xff00;
            temp += (hdr_head[i + 1] & 0x00ff);
            sum = cksm_add(sum, temp);
        }
    }

    for (int i = 0; i < plen; i += 2)
    {
        u_int16_t temp;
        if (i + 2 > plen)
        {
            temp = (pl[i] << 8u) & 0xff00;
            sum = cksm_add(sum, temp);
        }
        else
        {
            temp = ((pl[i] << 8u) & 0xff00);
            temp += (pl[i + 1] & 0x00ff);
            sum = cksm_add(sum, temp);
        }
    }
    u_int16_t result = ((~sum) & 0x0000ffff);

    return htons(result);
}

uint8_t *dissect_tcp(Net *net, Txp *self, uint8_t *segm, size_t segm_len)
{
    // [TODO]: Collect information from segm
    // (Check IP addr & port to determine the next seq and ack value)
    // Return payload of TCP

    self->thdr = *(struct tcphdr *)(segm);
    self->hdrlen = sizeof(struct tcphdr);
    self->pl = segm + sizeof(struct tcphdr);
    self->plen = segm_len - sizeof(struct tcphdr);

    return segm + sizeof(struct tcphdr);
}

Txp *fmt_tcp_rep(Txp *self, struct iphdr iphdr, uint8_t *data, size_t dlen)
{
    // [TODO]: Fill up self->tcphdr (prepare to send)
    self->thdr.seq = htonl(self->x_tx_seq);
    self->thdr.ack_seq = htonl(self->x_tx_ack);
    memcpy(self->pl, data, dlen);
    self->thdr.check = cal_tcp_cksm(iphdr, self->thdr, self->pl, self->plen);
    memcpy(self->pl - sizeof(struct tcphdr), &self->thdr, sizeof(struct tcphdr));
    return self;
}

inline void init_txp(Txp *self)
{
    self->pl = (uint8_t *)malloc(IP_MAXPACKET * sizeof(uint8_t));
    self->hdrlen = sizeof(struct tcphdr);

    self->dissect = dissect_tcp;
    self->fmt_rep = fmt_tcp_rep;
}
