/*
 * transport.c
 *
 * EN.601.414/614: HW#3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file.
 *
 */

/*
Provided API:
stcp_wait_for_event()
stcp_network_recv()
stcp_network_send()
stcp_unblock_application()
stcp_app_recv()
stcp_app_send()

- Both SYN and FIN sequence numbers are associated with one byte of the sequence
    space which allows the sequence number acking mechanism to handle SYN
    and non-data bearing FIN packets despite the fact that there is no
    actual associated payload.
- The sequence number should always be set in every packet.
- If the packet is a pure ACK packet (i.e., no data,
    and the SYN/FIN flags are nut) the sequence number should
    be set to the next unsent sequence
- Initial sequence number can be chosen randomly.

- max payload size is 536 bytes (STCP_MSS)
- local and remote window sizes are 3072 bytes

- TCP_DATA_START,  TCP_OPTIONS_LEN
- th_flags, th_win, th_seq, th_ack

- SYN-ACK = ACK = SYN
*/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <arpa/inet.h>
#include <time.h>

#define MAC_WIN_SIZE 3072
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

enum
{
    CSTATE_ESTABLISHED,
    FIN_WAIT_1,         
    FIN_WAIT_2,         
    CLOSE_WAIT_PASSIVE, 
    TIME_WAIT,  
    CSTATE_CLOSED
};

typedef struct
{
    bool_t done;
    int connection_state;
    ssize_t received_window_size;
    tcp_seq initial_sequence_num;
    tcp_seq received_sequence_num;
    tcp_seq current_sequence_num;
    tcp_seq server_sequence_num;
    tcp_seq tracked_sequence_num;
} context_t;

void our_dprintf(const char *format, ...);
static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);
static void buffer_control_APP_DATA(mysocket_t sd, context_t *ctx);
static void host_to_network(STCPHeader *header);
static void network_to_host(STCPHeader *header);

static void host_to_network(STCPHeader *header)
{
    header->th_win = htons(header->th_win);
    header->th_seq = htonl(header->th_seq);
    header->th_ack = htonl(header->th_ack);
}

static void network_to_host(STCPHeader *header)
{
    header->th_win = ntohs(header->th_win);
    header->th_seq = ntohl(header->th_seq);
    header->th_ack = ntohl(header->th_ack);
}

static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    srand(time(NULL));
    ctx->initial_sequence_num = rand() % 256;
#endif
}

void our_dprintf(const char *format, ...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}

void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;
    ctx = (context_t *)calloc(1, sizeof(context_t));
    assert(ctx);
    generate_initial_seq_num(ctx);

    STCPHeader *header = (STCPHeader *)malloc(sizeof(STCPHeader));
    memset(header, 0, sizeof(STCPHeader));
    ssize_t packet_size;
    STCPHeader *packet_hdr;
    char *pkt_allocate = (char *)malloc(556);

    if (is_active)
    {
        // send syn packet
        ctx->current_sequence_num = ctx->initial_sequence_num;
        ctx->tracked_sequence_num = ctx->current_sequence_num;
        memset(header, 0, sizeof(STCPHeader));
        header->th_flags = TH_SYN;
        header->th_seq = ctx->current_sequence_num;
        header->th_win = MAC_WIN_SIZE;
        header->th_off = 5;
        host_to_network(header);
        stcp_network_send(sd, header, sizeof(STCPHeader), NULL);
        ctx->current_sequence_num++;

        // wait for syn ack
        memset(pkt_allocate, 0, 556);
        packet_size = stcp_network_recv(sd, pkt_allocate, 3072);
        packet_hdr = (STCPHeader *)pkt_allocate;
        network_to_host(packet_hdr);
        ctx->received_window_size = packet_hdr->th_win;
        ctx->received_sequence_num = packet_hdr->th_seq + 1;
        ctx->tracked_sequence_num = ctx->current_sequence_num;
        ctx->server_sequence_num = packet_hdr->th_ack;

        // send ack
        memset(header, 0, sizeof(STCPHeader));
        header->th_flags = TH_ACK;
        header->th_seq = ctx->current_sequence_num;
        header->th_win = htons(MAC_WIN_SIZE);
        header->th_off = 5;
        header->th_ack = ctx->received_sequence_num;
        host_to_network(header);
        stcp_network_send(sd, header, sizeof(STCPHeader), NULL);
    }

    else
    {
        // wait for syn
        memset(pkt_allocate, 0, 556);
        packet_size = stcp_network_recv(sd, pkt_allocate, 3072);
        packet_hdr = (STCPHeader *)pkt_allocate;
        network_to_host(packet_hdr);
        ctx->received_window_size = packet_hdr->th_win;
        ctx->received_sequence_num = packet_hdr->th_seq + 1;

        // send syn ack
        ctx->current_sequence_num = ctx->initial_sequence_num;
        memset(header, 0, sizeof(STCPHeader));
        header->th_flags = (TH_ACK | TH_SYN);
        header->th_seq = ctx->current_sequence_num;
        header->th_win = MAC_WIN_SIZE;
        header->th_off = 5;
        header->th_ack = ctx->received_sequence_num;
        host_to_network(header);
        stcp_network_send(sd, header, sizeof(STCPHeader), NULL);
        ctx->current_sequence_num++;

        // wait for ack
        memset(pkt_allocate, 0, 556);
        packet_size = stcp_network_recv(sd, pkt_allocate, 3072);
        packet_hdr = (STCPHeader *)pkt_allocate;
        network_to_host(packet_hdr);
        ctx->received_window_size = packet_hdr->th_win;
        ctx->received_sequence_num = packet_hdr->th_seq;
        ctx->server_sequence_num = packet_hdr->th_ack;
    }
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);
    control_loop(sd, ctx);
    free(ctx);
}

static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);

    STCPHeader *fin_header = (STCPHeader *)malloc(sizeof(STCPHeader));
    memset(fin_header, 0, sizeof(STCPHeader));

    char *nstcp_pkt;

    while (!ctx->done)
    {
        unsigned int event;
        event = stcp_wait_for_event(sd, ANY_EVENT, NULL);

        if (event & APP_DATA)
        {
            buffer_control_APP_DATA(sd, ctx);
        }

        if (event & NETWORK_DATA)
        {
            // memset(nstcp_pkt, 0, 556);
            nstcp_pkt = (char *)malloc(556);
            ssize_t nk_pkt_size = stcp_network_recv(sd, nstcp_pkt, 3072);
            STCPHeader *nstcp_hdr = (STCPHeader *)nstcp_pkt;

            network_to_host(nstcp_hdr);
            ssize_t cal_result = nstcp_hdr->th_seq - 20 + nk_pkt_size;
            ctx->received_window_size = nstcp_hdr->th_win;
            ctx->received_sequence_num = cal_result;
            if (nstcp_hdr->th_flags != TH_ACK)
            {
                memset(fin_header, 0, sizeof(STCPHeader));
                fin_header->th_flags = TH_ACK;
                fin_header->th_ack = ctx->received_sequence_num;
                fin_header->th_seq = ctx->current_sequence_num;
                fin_header->th_win = MAC_WIN_SIZE;
                fin_header->th_off = 5;
                host_to_network(fin_header);
                stcp_network_send(sd, fin_header, sizeof(STCPHeader), NULL);
                ctx->tracked_sequence_num = ctx->current_sequence_num;
            }

            if (nstcp_hdr->th_flags == TH_ACK || nstcp_hdr->th_flags == (TH_FIN | TH_ACK))
            {
                ctx->server_sequence_num = ntohl(nstcp_hdr->th_ack);
                if (ctx->connection_state == TIME_WAIT)
                {
                    ctx->connection_state = CSTATE_CLOSED;
                    ctx->done = TRUE;
                }
                if (ctx->connection_state == FIN_WAIT_1)
                {
                    ctx->connection_state = FIN_WAIT_2;
                }
            }
            else if (nstcp_hdr->th_flags == TH_FIN || nstcp_hdr->th_flags == (TH_FIN | TH_ACK))
            {

                if (ctx->connection_state == CSTATE_ESTABLISHED)
                {
                    ctx->connection_state = CLOSE_WAIT_PASSIVE;
                }
                else if (ctx->connection_state == FIN_WAIT_2)
                {
                    ctx->connection_state = CSTATE_CLOSED;
                    ctx->done = TRUE;
                }
                if (nstcp_hdr->th_flags == TH_FIN)
                {
                    stcp_fin_received(sd);
                }
                else if (ctx->connection_state == TIME_WAIT)
                {
                    stcp_fin_received(sd);
                    ctx->connection_state = CSTATE_CLOSED;
                    ctx->done = TRUE;
                }
            }
            // last paylaod
            if (nk_pkt_size > 20)
                stcp_app_send(sd, nstcp_pkt + 20, nk_pkt_size - 20);
            free(nstcp_pkt);
        }
        if (event & APP_CLOSE_REQUESTED)
        {
            // send fin
            ctx->current_sequence_num = ctx->initial_sequence_num;
            memset(fin_header, 0, sizeof(STCPHeader));
            fin_header->th_flags = TH_FIN;
            fin_header->th_seq = ctx->current_sequence_num;
            fin_header->th_win = MAC_WIN_SIZE;
            fin_header->th_off = 5;
            host_to_network(fin_header);
            stcp_network_send(sd, fin_header, sizeof(STCPHeader), NULL);
            ctx->tracked_sequence_num = ctx->current_sequence_num;
            ctx->current_sequence_num += 1;

            if (ctx->connection_state == CSTATE_ESTABLISHED)
                ctx->connection_state = FIN_WAIT_1;
            else if (ctx->connection_state == CLOSE_WAIT_PASSIVE)
                ctx->connection_state = TIME_WAIT;
        }
    }
}

static void buffer_control_APP_DATA(mysocket_t sd, context_t *ctx)
{
    ctx->tracked_sequence_num = ctx->server_sequence_num;
    ssize_t cur_num = ctx->current_sequence_num;
    ssize_t tracked_num = ctx->tracked_sequence_num;
    if (cur_num > tracked_num && cur_num - tracked_num >= ctx->received_window_size)
            return;
    char *data_buffer = (char *)malloc(STCP_MSS);

    ssize_t cur_winn = (cur_num - tracked_num);
    if(cur_num <= tracked_num){
        cur_winn = 0;
    }
    ssize_t nk_pkt_size = stcp_app_recv(sd, data_buffer, MIN((ctx->received_window_size - cur_winn), STCP_MSS));
    char *packet = (char *)malloc(20 + nk_pkt_size);
    STCPHeader *packet_hdr = (STCPHeader *)packet;
    packet_hdr->th_seq = cur_num;
    packet_hdr->th_off = 5;
    packet_hdr->th_flags = 0;
    packet_hdr->th_win = 3072;
    memcpy(packet + sizeof(STCPHeader), data_buffer, nk_pkt_size);
    host_to_network(packet_hdr);    
    stcp_network_send(sd, (const void *)packet, sizeof(STCPHeader) + nk_pkt_size, NULL);
    ctx->current_sequence_num += nk_pkt_size;
}
 