#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <linux/pfkeyv2.h>

#include "esp.h"
#include "transport.h"
#include "hmac.h"

EspHeader esp_hdr_rec;

void get_ik(int type, uint8_t *key)
{
    // [TODO]: Dump authentication key from security association database (SADB)
    // (Ref. RFC2367 Section 2.3.4 & 2.4 & 3.1.10)

    int s;
    uint8_t buf[4096];
    struct sadb_msg msg;
    bzero(&msg, sizeof(msg));

    /* Build and write SADB_DUMP request */
    msg.sadb_msg_version = PF_KEY_V2;
    msg.sadb_msg_type = SADB_DUMP;
    msg.sadb_msg_satype = type;
    msg.sadb_msg_len = sizeof(msg) / 8; // 1 word = 8 bytes
    msg.sadb_msg_pid = getpid();

    s = socket(PF_KEY, SOCK_RAW, PF_KEY_V2);
    if (s < 0)
    {
        perror("socket():");
        exit(EXIT_FAILURE);
    }
    write(s, &msg, sizeof(msg));

    int msglen;
    msglen = read(s, &buf, sizeof(buf));
    if (msglen < 0)
    {
        perror("read():");
        exit(EXIT_FAILURE);
    }

    size_t i = 0;
    uint8_t *temp = &buf[0];   // point to the head of returned msg
    struct sadb_msg *temp_msg; // first is sadb_msg
    temp_msg = (struct sadb_msg *)temp;
    temp += (sizeof(struct sadb_msg) * 8);
    i = sizeof(struct sadb_msg);

    while (i < temp_msg->sadb_msg_len)
    {
        struct sadb_ext *temp_ext;
        temp_ext = (struct sadb_ext *)temp;
        i += temp_ext->sadb_ext_len;
        if (temp_ext->sadb_ext_type == SADB_EXT_KEY_AUTH)
        {
            temp += sizeof(struct sadb_key);                                       // 8 bytes
            size_t key_len = temp_ext->sadb_ext_len * 8 - sizeof(struct sadb_key); // key_len = ext_len - header
            memcpy(key, temp, key_len);                                            // b1 f8 84 fc 3b c1 b6 1a a0 c7 c8 bc de 3e 1b 7b
            temp += key_len;
        }
        else
        {
            temp += temp_ext->sadb_ext_len * 8;
        }
    }
    close(s);
    return;
}

void get_esp_key(Esp *self)
{
    get_ik(SADB_SATYPE_ESP, self->esp_key);
}

uint8_t *set_esp_pad(Esp *self)
{
    // [TODO]: Fiill up self->pad and self->pad_len (Ref. RFC4303 Section 2.4)

    self->tlr.pad_len = (self->plen % 4 == 0) ? 0 : 4 - self->plen % 4; // 4 byte boundary
    self->pad = self->pl + self->plen;
    int i = 0;
    for (i = 0; i < self->tlr.pad_len; i++)
    {
        uint8_t temp = i + 1;
        memcpy(self->pad + i, &temp, sizeof(uint8_t));
    }
    memcpy(self->pad + self->tlr.pad_len, &self->tlr, sizeof(EspTrailer));
    return self->pad;
}

uint8_t *set_esp_auth(Esp *self,
                      ssize_t (*hmac)(uint8_t const *, size_t,
                                      uint8_t const *, size_t,
                                      uint8_t *))
{
    if (!self || !hmac)
    {
        fprintf(stderr, "Invalid arguments of %s().\n", __func__);
        return NULL;
    }

    uint8_t buff[BUFSIZE];
    size_t esp_keylen = 16;
    size_t nb = 0; // Number of bytes to be hashed
    ssize_t ret;

    // [TODO]: Put everything needed to be authenticated into buff and add up nb
    self->auth = self->pl + self->plen + sizeof(EspTrailer) + self->tlr.pad_len;
    nb = sizeof(EspHeader) + self->plen + self->tlr.pad_len + sizeof(EspTrailer);
    memcpy(buff, self->pl - sizeof(EspHeader), nb);

    ret = hmac(self->esp_key, esp_keylen, buff, nb, self->auth);

    if (ret == -1)
    {
        fprintf(stderr, "Error occurs when try to compute authentication data");
        return NULL;
    }

    self->authlen = ret;
    return self->auth;
}

uint8_t *dissect_esp(Esp *self, uint8_t *esp_pkt, size_t esp_len)
{
    // [TODO]: Collect information from esp_pkt.
    // Return payload of ESP

    self->hdr = *(EspHeader *)esp_pkt;
    self->pl = esp_pkt + sizeof(EspHeader);                             // point to the head of esp payload
    self->plen = esp_len - sizeof(EspHeader) - sizeof(EspTrailer) - 12; // esp_len - header_len -trailer_len - authlen
    self->tlr = *(EspTrailer *)(self->pl + self->plen);
    self->pad = self->pl + self->plen - self->tlr.pad_len;
    self->auth = self->pl + self->plen + sizeof(EspTrailer);
    self->plen -= self->tlr.pad_len;
    self->authlen = 12;

    return esp_pkt + sizeof(EspHeader);
}

Esp *fmt_esp_rep(Esp *self, Proto p)
{
    // [TODO]: Fill up ESP header and trailer (prepare to send)

    self->hdr.seq = ntohl(ntohl(self->hdr.seq) + 1);
    memcpy(self->pl - sizeof(uint32_t), &self->hdr.seq, sizeof(uint32_t));

    return self;
}

void init_esp(Esp *self)
{
    self->pl = (uint8_t *)malloc(MAXESPPLEN * sizeof(uint8_t));
    self->pad = (uint8_t *)malloc(MAXESPPADLEN * sizeof(uint8_t));
    self->auth = (uint8_t *)malloc(HMAC96AUTHLEN * sizeof(uint8_t));
    self->authlen = HMAC96AUTHLEN;
    self->esp_key = (uint8_t *)malloc(BUFSIZE * sizeof(uint8_t));

    self->set_padpl = set_esp_pad;
    self->set_auth = set_esp_auth;
    self->get_key = get_esp_key;
    self->dissect = dissect_esp;
    self->fmt_rep = fmt_esp_rep;
}
