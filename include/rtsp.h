
#ifndef _RTSP_H
#define _RTSP_H


#define trace_point() 	do {printf("rtsp_tracepoint: %s,%s,%d\n",__FILE__,__FUNCTION__,__LINE__); } while(0)			//10728

/*error codes define,yanf*/
#define ERR_NOERROR          0
#define ERR_GENERIC             -1
#define ERR_NOT_FOUND       -2
#define ERR_PARSE           -3
#define ERR_ALLOC               -4
#define ERR_INPUT_PARAM         -5
#define ERR_NOT_SD          -6
#define ERR_UNSUPPORTED_PT      -7
#define ERR_EOF             -8
#define ERR_FATAL                   -9
#define ERR_CONNECTION_CLOSE        -10

/* ��Ϣͷ�ؼ��� */
#define HDR_CONTENTLENGTH "Content-Length"
#define HDR_ACCEPT "Accept"
#define HDR_ALLOW "Allow"
#define HDR_BLOCKSIZE "Blocksize"
#define HDR_CONTENTTYPE "Content-Type"
#define HDR_DATE "Date"
#define HDR_REQUIRE "Require"
#define HDR_TRANSPORTREQUIRE "Transport-Require"
#define HDR_SEQUENCENO "SequenceNo"
#define HDR_CSEQ "CSeq"
#define HDR_STREAM "Stream"
#define HDR_SESSION "Session"
#define HDR_TRANSPORT "Transport"
#define HDR_RANGE "Range"
#define HDR_USER_AGENT "User-Agent"


/*rtsp����*/
#define RTSP_METHOD_MAXLEN 15
#define RTSP_METHOD_DESCRIBE "DESCRIBE"
#define RTSP_METHOD_ANNOUNCE "ANNOUNCE"
#define RTSP_METHOD_GET_PARAMETERS "GET_PARAMETERS"
#define RTSP_METHOD_OPTIONS "OPTIONS"
#define RTSP_METHOD_PAUSE "PAUSE"
#define RTSP_METHOD_PLAY "PLAY"
#define RTSP_METHOD_RECORD "RECORD"
#define RTSP_METHOD_REDIRECT "REDIRECT"
#define RTSP_METHOD_SETUP "SETUP"
#define RTSP_METHOD_SET_PARAMETER "SET_PARAMETER"
#define RTSP_METHOD_TEARDOWN "TEARDOWN"


/*rtsp�����Ǻ�ID*/
#define RTSP_ID_DESCRIBE 0
#define RTSP_ID_ANNOUNCE 1
#define RTSP_ID_GET_PARAMETERS 2
#define RTSP_ID_OPTIONS 3
#define RTSP_ID_PAUSE 4
#define RTSP_ID_PLAY 5
#define RTSP_ID_RECORD 6
#define RTSP_ID_REDIRECT 7
#define RTSP_ID_SETUP 8
#define RTSP_ID_SET_PARAMETER 9
#define RTSP_ID_TEARDOWN 10

/*		RTSP ���		*/
#define RTSP_not_full 0
#define RTSP_method_rcvd 1
#define RTSP_interlvd_rcvd 2

#define RTSP_BUFFERSIZE 4096
#define MAX_DESCR_LENGTH 4096
#define RTCP_BUFFERSIZE	1024


/* Stati della macchina a stati del server rtsp*/
#define INIT_STATE      0
#define READY_STATE     1
#define PLAY_STATE      2

#define RTSP_VER "RTSP/1.0"

#define RTSP_EL "\r\n"

#define PACKAGE "RTSP SERVER"
#define VERSION "1.11"

//extern struct _tagStRtpHandle *HndRtp;
#include "rtp.h"



typedef struct _RTSP_session {
    int cur_state;   /*�Ự״̬*/
    int session_id; /*�Ự��ID*/

    RTP_session *rtp_session; /*RTP�Ự*/

    struct _RTSP_session *next; /*��һ���Ự��ָ�룬��������ṹ*/
} RTSP_session;


typedef struct _RTSP_buffer {
    int fd;    /*socket�ļ�������*/
    unsigned int port;/*�˿ں�*/
	int iNeedClose;

    struct sockaddr stClientAddr;

    char in_buffer[RTSP_BUFFERSIZE];/*���ջ�����*/
    unsigned int in_size;/*���ջ������Ĵ�С*/
    char out_buffer[RTSP_BUFFERSIZE+MAX_DESCR_LENGTH];/*���ͻ�����*/
    int out_size;/*���ͻ�������С*/
    
    unsigned int rtsp_cseq;/*���к�*/
    char descr[MAX_DESCR_LENGTH];/*����*/
    RTSP_session *session_list;/*�Ự����*/
    struct _RTSP_buffer *next; /*ָ����һ���ṹ�壬����������ṹ*/
} RTSP_buffer;

typedef struct _stVideoAttr
{
	unsigned short nPpsLen;
	unsigned short nSpsLen;
	char     	   szPpsBuf[64];
	char     	   szSpsBuf[64];
	
} VIDEOATTR,*PVIDEOATTR;


/*		tcp���				*/
char *sock_ntop_host(const struct sockaddr *sa, socklen_t salen, char *str, size_t len);
int tcp_accept(int fd);
int tcp_connect(unsigned short port, char *addr);
int tcp_listen(unsigned short port);
int tcp_read(int fd, void *buffer, int nbytes, struct sockaddr *Addr);
int tcp_send(int fd, void *dataBuf, unsigned int dataSize);
int tcp_write(int fd, char *buffer, int nbytes);
void tcp_close(int s);

void ScheduleConnections(RTSP_buffer **rtsp_list, int *conn_count);
void AddClient(RTSP_buffer **ppRtspList, int fd);
void RTP_port_pool_init(int port,int iMax);
const char *get_stat(int err);
RTP_session *RTP_session_destroy(RTP_session *session);





#endif /* _RTSP_H */
