




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
*/

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"
#include <arpa/inet.h>

#define MAX_WINDOW_SIZE 3072
enum
{
    CSTATE_ESTABLISHED,
    CSTATE_CLOSE_WAIT,
    CSTATE_CLOSED,
    CSTATE_SYN_SENT,
    CSTATE_SYN_RCVD,
    CSTATE_FIN_WAIT_1,
    CSTATE_FIN_WAIT_2,
    CSTATE_CLIENT_DONE,
    CSTATE_SERVER_DONE,
    CSTATE_LAST_ACK
}; /* obviously you should have more states */

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;          /* TRUE once connection is closed */
    int connection_state; /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;

    bool_t is_active;

    tcp_seq cwnd_size;
    tcp_seq current_seq_ackd;
    tcp_seq cwnd_num_unacked_bytes;

    tcp_seq rwnd_max_size;
    tcp_seq rcvd_seq_num;
    tcp_seq rwnd_last_processed_byte;

    tcp_seq fin_ack_num;
    tcp_seq ack_num;

} context_t;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);

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

/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx = (context_t *)calloc(1, sizeof(context_t));
    assert(ctx);

    generate_initial_seq_num(ctx);

    STCPHeader *stcp_hdr = (STCPHeader *)calloc(1, sizeof(STCPHeader));
    assert(stcp_hdr);

    ctx->current_seq_ackd = ctx->initial_sequence_num;
    // ctx->cwnd_num_unacked_bytes = 0;

    ctx->rwnd_max_size = MAX_WINDOW_SIZE;
    ctx->rcvd_seq_num = 0;
    ctx->rwnd_last_processed_byte = 0;
    // ctx->is_active = is_active;
    // ctx->connection_state = is_active ? CSTATE_SYN_SENT : CSTATE_SYN_RCVD;

    if (is_active)
    {
        // send syn
        printf("sending syn\n");
        stcp_hdr->th_seq = ctx->current_seq_ackd;
        stcp_hdr->th_flags = TH_SYN;
        stcp_hdr->th_win = ctx->rwnd_max_size;
        host_to_network(stcp_hdr);
        stcp_network_send(sd, stcp_hdr, sizeof(STCPHeader), NULL);
        ctx->current_seq_ackd++;

        // wait for syn ack
        memset(stcp_hdr, 0, 20);
        printf("waiting for syn ack\n");
        stcp_network_recv(sd, stcp_hdr, sizeof(STCPHeader));
        network_to_host(stcp_hdr);
        if (stcp_hdr->th_flags & TH_SYN && stcp_hdr->th_flags & TH_ACK)
        {
            ctx->rcvd_seq_num = stcp_hdr->th_seq;
            ctx->rwnd_last_processed_byte = stcp_hdr->th_seq;
            ctx->cwnd_size = stcp_hdr->th_win;
        }

        // handle ack
        memset(stcp_hdr, 0, 20);
        printf("sending ack\n");
        stcp_hdr->th_seq = ctx->current_seq_ackd;
        stcp_hdr->th_ack = ctx->rcvd_seq_num + 1;
        stcp_hdr->th_flags = TH_ACK;
        stcp_hdr->th_win = ctx->rwnd_max_size;
        ctx->current_seq_ackd++;
        host_to_network(stcp_hdr);
        stcp_network_send(sd, stcp_hdr, sizeof(STCPHeader), NULL);
    }
    else
    {
        // wait for syn
        printf("waiting for syn\n");
        stcp_network_recv(sd, stcp_hdr, sizeof(STCPHeader));
        network_to_host(stcp_hdr);

        if (!(stcp_hdr->th_flags & TH_SYN))
        {
            printf("ECONNREFUSED");
            // exit(1);
        }
        ctx->rcvd_seq_num = stcp_hdr->th_seq;
        ctx->rwnd_last_processed_byte = stcp_hdr->th_seq;
        ctx->cwnd_size = stcp_hdr->th_win;

        // send syn ack
        memset(stcp_hdr, 0, 20);
        printf("sending syn ack\n");
        stcp_hdr->th_seq = ctx->current_seq_ackd;
        stcp_hdr->th_ack = ctx->rcvd_seq_num + 1;
        stcp_hdr->th_flags = TH_SYN | TH_ACK;
        stcp_hdr->th_win = ctx->rwnd_max_size;
        host_to_network(stcp_hdr);
        stcp_network_send(sd, stcp_hdr, sizeof(STCPHeader), NULL);
        ctx->current_seq_ackd += 1; // syn is one byte of seq space

        // wait for ack
        memset(stcp_hdr, 0, 20);
        printf("waiting for ack\n");
        stcp_network_recv(sd, stcp_hdr, sizeof(STCPHeader));
        network_to_host(stcp_hdr);
        if (!(stcp_hdr->th_flags & TH_ACK))
        {
            printf("ECONNREFUSED");
            // exit(1);
        }
        if (stcp_hdr->th_ack == ctx->current_seq_ackd)
        {
            ctx->rcvd_seq_num = stcp_hdr->th_seq;
            ctx->rwnd_last_processed_byte = stcp_hdr->th_seq;
            ctx->cwnd_size = stcp_hdr->th_win;
        }
    }
    printf("connection established\n");
    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);

    /* do any cleanup here */
    free(ctx);
}

/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);

#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    ctx->initial_sequence_num = rand() % 256;
#endif
}

static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    assert(!ctx->done);
    STCPHeader *stcp_hdr = (STCPHeader *)calloc(1, sizeof(STCPHeader));

    char *payload;
    char *payload1;
    int pkt_size;
    int cur_win;
    int payload_size;

    while (!ctx->done)
    {
        unsigned int event = stcp_wait_for_event(sd, ANY_EVENT, NULL);
        // didididididididi
        cur_win = MAX_WINDOW_SIZE - (ctx->current_seq_ackd - ctx->ack_num);

        if (event & NETWORK_DATA)
        {
            printf("NETWORK_DATA\n");
            char *payload1 = (char *)calloc(1, 556);
            memset(payload1, 0, 556);
            memset(stcp_hdr, 0, 20);
            // stcp_hdr = (STCPHeader *)calloc(1, 556);  //无限循环罪魁祸首,草他妈的.
            stcp_hdr = (STCPHeader *)payload1;

            pkt_size = stcp_network_recv(sd, payload1, STCP_MSS + sizeof(STCPHeader));

            network_to_host(stcp_hdr);
            ctx->cwnd_size = stcp_hdr->th_win;

            // handle ack
            // printf("handling ack, NETWORKDATA\n");
            if (stcp_hdr->th_flags & TH_ACK)
            {
                network_to_host(stcp_hdr);
                printf("NETWORK_DATA :TH_ACK\n");
                // tcp_seq yizhi = (stcp_hdr->th_ack);
                ctx->ack_num = stcp_hdr->th_ack;
                // ctx->current_seq_ackd = stcp_hdr->th_ack;
                // ctx->cwnd_num_unacked_bytes -= yizhi;
                ctx->cwnd_size = stcp_hdr->th_win;

                // if (ntohl(stcp_hdr->th_ack) == ctx->fin_ack_num)
                // {
                    printf("到此一游!!!\n");
                    if (ctx->connection_state == CSTATE_FIN_WAIT_1)
                    {
                        ctx->connection_state = CSTATE_FIN_WAIT_2;
                    }
                    // else if(ctx->connection_state == CSTATE_LAST_ACK)
                    // {
                    //     ctx->connection_state = CSTATE_CLOSED;
                    // }
                // }
            }

            // handle fin
            else if (stcp_hdr->th_flags & TH_FIN)
            {
                printf("NETWORK_DATA :TH_FIN\n");
                stcp_fin_received(sd);

                network_to_host(stcp_hdr);
                ctx->rcvd_seq_num = stcp_hdr->th_seq;
                ctx->rwnd_last_processed_byte = stcp_hdr->th_seq;
                ctx->cwnd_size = stcp_hdr->th_win;
                
                if (pkt_size > 20)
                {
                    payload1 = payload1 + 20;
                    payload_size = pkt_size - 20;
                    stcp_app_send(sd, payload1, payload_size);
                }

                if (ctx->connection_state == CSTATE_CLIENT_DONE)
                {
                    ctx->connection_state = CSTATE_CLOSED;
                    ctx->done = TRUE;
                }
                // ctx->connection_state = CSTATE_SERVER_DONE;
                // ctx->rcvd_seq_num += 1;

                // send ACK;
                //  stcp_hdr->th_seq = ctx->current_seq_ackd + ctx->cwnd_num_unacked_bytes;
                memset(stcp_hdr, 0, 20);
                stcp_hdr->th_win = ctx->rwnd_max_size;
                stcp_hdr->th_flags = TH_ACK;
                stcp_hdr->th_ack = ctx->rcvd_seq_num + 1;
                host_to_network(stcp_hdr);
                pkt_size = stcp_network_send(sd, stcp_hdr, sizeof(STCPHeader), NULL);

                // ctx->connection_state = CSTATE_CLOSE_WAIT;
                if (ctx->connection_state == CSTATE_ESTABLISHED)
                {
                    ctx->connection_state = CSTATE_CLOSE_WAIT;
                }
                else if (ctx->connection_state == CSTATE_FIN_WAIT_2)
                {
                    ctx->connection_state = CSTATE_CLOSED;
                    ctx->done = TRUE;
                    printf("上面结束\n");
                }
                // else if(ctx->connection_state == CSTATE_LAST_ACK)
                // {
                //     ctx->connection_state = CSTATE_CLOSED;
                //     ctx->done = TRUE;
                // }
                
                // else{
                //     ctx->connection_state = CSTATE_CLOSED;
                //     ctx->done = TRUE;
                // }
            }
 
            else
            {
                printf("NETWORK_DATA :ELSE\n");
                network_to_host(stcp_hdr);
                ctx->rcvd_seq_num = stcp_hdr->th_seq;
                ctx->rwnd_max_size = stcp_hdr->th_win;
                ctx->rwnd_last_processed_byte = stcp_hdr->th_seq;
                memset(stcp_hdr, 0, 20);

                payload1 = payload1 + 20;
                payload_size = pkt_size - sizeof(STCPHeader);
                stcp_app_send(sd, payload1, payload_size);

                memset(stcp_hdr, 0, 20);
                stcp_hdr->th_win = ctx->rwnd_max_size;
                stcp_hdr->th_flags = TH_ACK;
                stcp_hdr->th_ack = ctx->rcvd_seq_num + payload_size;
                host_to_network(stcp_hdr);

                // printf("not ack not fin, 发送啦!!\n");
                stcp_network_send(sd, stcp_hdr, sizeof(STCPHeader), NULL);
            }
        }

        if ((event & APP_DATA) && (cur_win > 0))
        {
            int max_payload; //////////////////
            printf("APP_DATA\n");
            char *stcp_buffer = (char *)calloc(1, MAX_WINDOW_SIZE);
            memset(stcp_buffer, 0, MAX_WINDOW_SIZE);
            payload_size = stcp_app_recv(sd, stcp_buffer, cur_win);
            // printf("即将进入小循环啦.");
            while (payload_size > 0)
            {
                memset(stcp_hdr, 0, 20);
                network_to_host(stcp_hdr);
                stcp_hdr->th_seq = ctx->current_seq_ackd;
                stcp_hdr->th_win = ctx->rwnd_max_size;
                // stcp_hdr->th_flags = 0;

                host_to_network(stcp_hdr);
                if (payload_size > STCP_MSS)
                {
                    max_payload = stcp_network_send(sd, stcp_hdr, sizeof(STCPHeader), stcp_buffer, STCP_MSS, NULL);
                    max_payload = STCP_MSS;
                }
                else
                {
                    max_payload = stcp_network_send(sd, stcp_hdr, sizeof(STCPHeader), stcp_buffer, payload_size, NULL);
                    max_payload = max_payload - sizeof(STCPHeader);
                }
                // stcp_network_send(sd, stcp_hdr, sizeof(STCPHeader), stcp_buffer, max_payload, NULL);

                ctx->current_seq_ackd = ctx->current_seq_ackd + max_payload;
                stcp_buffer = stcp_buffer + max_payload;
                payload_size = payload_size - max_payload;
                // printf("循环里头发送stcp完毕!");
            }
            // printf("循环结束啦.\n");
        }

        if (event & APP_CLOSE_REQUESTED)
        {
            printf("APP_CLOSE_REQUESTED\n");
            memset(stcp_hdr, 0, 20);
            // Create the packet
            stcp_hdr->th_seq = ctx->current_seq_ackd;
            // stcp_hdr->th_ack = 0; // not an ack
            stcp_hdr->th_flags = TH_FIN;
            stcp_hdr->th_win = ctx->rwnd_max_size;
            ctx->current_seq_ackd += 1;
            // Send over network
            host_to_network(stcp_hdr);
            pkt_size = (sd, stcp_hdr, sizeof(STCPHeader), NULL);
            if (ctx->connection_state == CSTATE_ESTABLISHED)
            {
                // printf("11111111111111111111111\n");
                ctx->connection_state = CSTATE_FIN_WAIT_1;
            }
            else
            {   
                // printf("22222222222222222222222\n");
                ctx->connection_state = CSTATE_LAST_ACK;
                ctx->done = TRUE;
                ctx->connection_state = CSTATE_CLOSED;
                printf("下面结束\n");
            }
            // if (ctx->connection_state == CSTATE_SERVER_DONE)
            // {
            // }
            // ctx->connection_state = CSTATE_CLIENT_DONE;
            ctx->fin_ack_num = ctx->current_seq_ackd;
            // printf("APP_CLOSE_REQUESTED, 正式结束\n");
        }
    }
}

/**********************************************************************/
/* our_dprintf
 *
 * Send a formatted message to stdout.
 *
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
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