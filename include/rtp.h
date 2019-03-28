#ifndef _RTP_H_
#define _RTP_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>

#define MAX_RTP_PKT_LENGTH      1024
#define RTCP_BUFFERSIZE			1024


#define P_H264                  96

#define P_G711A					8
#define P_G711U					0


typedef enum
{	
	_unkonw=0,
	_h264	,
	_h264nalu,
	_mjpeg,
	_g711
}EmRtpPayload;

typedef enum  {
	i_server=0,
	i_client=1
} rtcp_index;

typedef struct
{
        int RTP;
        int RTCP;
} port_pair;


typedef enum
{
    rtp_proto = 0,
    rtcp_proto
} rtp_protos;


typedef enum{
			RTP_no_transport=0,
            RTP_rtp_avp,
            RTP_rtp_avp_tcp
		} rtp_type;


typedef struct _RTP_transport
{
	rtp_type type;
	int rtp_fd;
	int rtcp_fd_out;
	int rtcp_fd_in;
	union{
#if 1
		struct {
				struct sockaddr rtp_peer;
				struct sockaddr rtcp_in_peer;
				struct sockaddr rtcp_out_peer;
				port_pair cli_ports;
				port_pair ser_ports;
				unsigned char is_multicast;
			} udp;
#endif
		struct {
				port_pair interleaved;
				} tcp;
            // other trasports here
		} u;
} RTP_transport;

typedef struct _RTCP_stats {
	unsigned int RR_received;
	unsigned int SR_received;
	unsigned long dest_SSRC;
	unsigned int pkt_count;
	unsigned int octet_count;
	int pkt_lost;
	unsigned char fract_lost;
	unsigned int highest_seq_no;
	unsigned int jitter;
	unsigned int last_SR;
	unsigned int delay_since_last_SR;
} RTCP_stats;

typedef struct _RTP_session {
	RTP_transport transport;
    unsigned char rtcp_inbuffer[RTCP_BUFFERSIZE];
    int rtcp_insize;
    unsigned char rtcp_outbuffer[RTCP_BUFFERSIZE];
	EmRtpPayload		emPayload;
    int rtcp_outsize;
    unsigned char pause;
    unsigned char started;
    int sched_id;
	int videoIndex;
	unsigned char byFirstTime;
	unsigned int u32SSrc;
	unsigned short nSeq;
	unsigned int u32TimeStamp;
	void *pRtsp;
	RTCP_stats rtcp_stats[2];
	struct _RTP_session *next;
}RTP_session;

#define msleep(x) usleep(1000 * x)
int RTP_sendto(RTP_session *session, rtp_protos proto,  char *pkt, ssize_t pkt_size);
int RtpSend(RTP_session *session, char *pData, int s32DataSize, unsigned int u32TimeStamp);
RTP_session *RTP_session_destroy(RTP_session *session);

#endif  /* _RTP_H_ */
