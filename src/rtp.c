#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include "pthread.h"
#include "rtp.h"
#include "rtsp.h"
#include "log.h"

typedef struct
{
    /**//* byte 0 */
    unsigned char u4CSrcLen:4;		/**//* expect 0 */
    unsigned char u1Externsion:1;	/**//* expect 1, see RTP_OP below */
    unsigned char u1Padding:1;		/**//* expect 0 */
    unsigned char u2Version:2;		/**//* expect 2 */
    /**//* byte 1 */
    unsigned char u7Payload:7;		/**//* RTP_PAYLOAD_RTSP */
    unsigned char u1Marker:1;		/**//* expect 1 */
    /**//* bytes 2, 3 */
    unsigned short u16SeqNum;
    /**//* bytes 4-7 */
    unsigned long u32TimeStamp;
    /**//* bytes 8-11 */
    unsigned long u32SSrc;			/**//* stream number is used here. */
}StRtpFixedHdr;

typedef struct{
	//byte 0
	unsigned char u5Type:5;
	unsigned char u2Nri:2;
	unsigned char u1F:1;
}StNaluHdr; /**//* 1 BYTES */

typedef struct
{
	//byte 0
	unsigned char u5Type:5;
	unsigned char u2Nri:2;
	unsigned char u1F:1;
}StFuIndicator; /**//* 1 BYTES */

typedef struct
{
	//byte 0
	unsigned char u5Type:5;
	unsigned char u1R:1;
	unsigned char u1E:1;
	unsigned char u1S:1;
}StFuHdr; /**//* 1 BYTES */


typedef struct
{
    /**//* byte 0 */
    unsigned char csrc_len:4;        /**//* expect 0 */
    unsigned char extension:1;        /**//* expect 1, see RTP_OP below */
    unsigned char padding:1;        /**//* expect 0 */
    unsigned char version:2;        /**//* expect 2 */
    /**//* byte 1 */
    unsigned char payload:7;        /**//* RTP_PAYLOAD_RTSP */
    unsigned char marker:1;        /**//* expect 1 */
    /**//* bytes 2, 3 */
    unsigned short seq_no;
    /**//* bytes 4-7 */
    unsigned  long timestamp;
    /**//* bytes 8-11 */
    unsigned long ssrc;            /**//* stream number is used here. */
} RTP_FIXED_HEADER;


typedef struct
{
  int startcodeprefix_len;      //! 4 for parameter sets and first slice in picture, 3 for everything else (suggested)
  int len;                 //! Length of the NAL unit (Excluding the start code, which does not belong to the NALU)
  int max_size;            //! Nal Unit Buffer size
  int forbidden_bit;            //! should be always FALSE
  int nal_reference_idc;        //! NALU_PRIORITY_xxxx
  int nal_unit_type;            //! NALU_TYPE_xxxx
  char *buf;                    //! contains the first byte followed by the EBSP
  unsigned short lost_packets;  //! true, if packet loss is detected
} NALU_t;




int SendOneNalu(RTP_session *session, char *pNalBuf, int s32NalBufSize)
{

    static  char szRtpBuf[1600];
    RTP_FIXED_HEADER *pstRtpHead;
    NALU_t stNalu;
    NALU_t *nalu = &stNalu;
    char *nalu_payload;
    int iPacketSize = 0;


    memset(szRtpBuf, 0, sizeof(szRtpBuf)); //
    pstRtpHead = (RTP_FIXED_HEADER *)szRtpBuf;
    pstRtpHead->payload     = P_H264;  //负载类型号，
    pstRtpHead->version     = 2;  //版本号，此版本固定为2
    pstRtpHead->marker    = 0;   //标志位，由具体协议规定其值。
    pstRtpHead->ssrc        = session->u32SSrc;//htonl(10);    //随机指定为10，并且在本RTP会话中全局唯一
    nalu->len = s32NalBufSize;
    nalu->buf = pNalBuf;
    nalu->forbidden_bit = 0; //1 bit
    nalu->nal_unit_type = (nalu->buf[0]) & 0x1f;// 5 bit

    nalu->nal_reference_idc = nalu->buf[0] & 0x60; // 2 bit

    if(nalu->len <= MAX_RTP_PKT_LENGTH)
    {
		
        pstRtpHead->marker = 1;
        pstRtpHead->seq_no = htons(session->nSeq++); 

        nalu_payload = szRtpBuf + 12;
        memcpy(nalu_payload, nalu->buf, nalu->len); 
        pstRtpHead->timestamp = htonl(session->u32TimeStamp);
        iPacketSize = nalu->len + 12;
		if(RTP_sendto(session,rtp_proto,szRtpBuf,iPacketSize)< 0)
		{
			return -1;
		}
    }
    else
    {

        int iSend = 0;

        pstRtpHead->timestamp =  htonl(session->u32TimeStamp);

        pstRtpHead->seq_no = htons(session->nSeq++); //序列号，每发送一个RTP包增1

        pstRtpHead->marker = 0;

        szRtpBuf[12] = nalu->buf[0] & 0xe0;
        szRtpBuf[12] += 0x1c;
        szRtpBuf[13] = 0x80 + (nalu->buf[0] & 0x1f);


        nalu_payload = szRtpBuf + 14; //同理将sendbuf[14]赋给nalu_payload
        memcpy(nalu_payload, nalu->buf+1, MAX_RTP_PKT_LENGTH-1);
        iPacketSize = MAX_RTP_PKT_LENGTH + 13;						//获得sendbuf的长度,为nalu的长度（除去起始前缀和NALU头）加上rtp_header，fu_ind，fu_hdr的固定长度14字节
        if(RTP_sendto(session,rtp_proto,szRtpBuf,iPacketSize)< 0)
		{
			return -1;
		}

		nalu->len-=MAX_RTP_PKT_LENGTH;
		iSend+=MAX_RTP_PKT_LENGTH;
		
        while(nalu->len > MAX_RTP_PKT_LENGTH)
        {
            pstRtpHead->seq_no = htons(session->nSeq++); //序列号，每发送一个RTP包增1
           
            pstRtpHead->marker = 0;
            szRtpBuf[12] = nalu->buf[0] & 0xe0;
            szRtpBuf[12] += 0x1c;
            szRtpBuf[13] = (nalu->buf[0] & 0x1f);
            nalu_payload = (szRtpBuf + 14); //同理将sendbuf[14]的地址赋给nalu_payload
            memcpy(nalu_payload, nalu->buf+iSend, MAX_RTP_PKT_LENGTH); //去掉起始前缀的nalu剩余内容写入sendbuf[14]开始的字符串。
			nalu->len-=MAX_RTP_PKT_LENGTH;
			iSend+=MAX_RTP_PKT_LENGTH;
			iPacketSize = MAX_RTP_PKT_LENGTH + 14;						//获得sendbuf的长度,为nalu的长度（除去原NALU头）加上rtp_header，fu_ind，fu_hdr的固定长度14字节
			if(RTP_sendto(session,rtp_proto,szRtpBuf,iPacketSize)< 0)
			{
				return -1;
			}
        }
		
		pstRtpHead->seq_no = htons(session->nSeq++);
        pstRtpHead->marker = 1;
        szRtpBuf[12] = nalu->buf[0] & 0xe0;
        szRtpBuf[12] += 0x1c;
        szRtpBuf[13] = 0x40 + (nalu->buf[0] & 0x1f);

        nalu_payload = (szRtpBuf + 14);
        memcpy(nalu_payload, nalu->buf + iSend,nalu->len); 
        iPacketSize = nalu->len + 14;
        if(RTP_sendto(session,rtp_proto,szRtpBuf,iPacketSize)< 0)
		{
			return -1;
		}
            
    }

    return 0;

}



static int SendNalu711(RTP_session *session, char *buf, int bufsize)
{
	char *pSendBuf;
	int	s32Bytes = 0;
//	unsigned char byAencType=g_stHLAllParam.stAudioParam.stAencParam[0].byEncType;
	StRtpFixedHdr *pRtpFixedHdr=NULL;
	
	static char szBuf[MAX_RTP_PKT_LENGTH + 100];
	memset(szBuf, 0, MAX_RTP_PKT_LENGTH + 100); //
	
	pSendBuf =szBuf;
	
	pRtpFixedHdr = (StRtpFixedHdr *)pSendBuf;
//	pRtpFixedHdr->u7Payload     = byAencType==AUDIO_TYPE_G711A?P_G711A:P_G711U;
	pRtpFixedHdr->u2Version     = 2;

	pRtpFixedHdr->u1Marker = 1;   //标志位，由具体协议规定其值。

	pRtpFixedHdr->u32SSrc = session->u32SSrc;

	pRtpFixedHdr->u16SeqNum  = htons(session->nSeq++);
	//////去掉前四个字节
	buf+=4;
	bufsize-=4;
	
	memcpy(pSendBuf + 12, buf, bufsize);

	pRtpFixedHdr->u32TimeStamp = htonl(session->u32TimeStamp);
	s32Bytes = bufsize + 12;
	if(RTP_sendto(session,rtp_proto,pSendBuf,s32Bytes)<0)
	{
		return -1;
	}

	return 0;
}


int RtpSend(RTP_session *session, char *pData, int s32DataSize, unsigned int u32TimeStamp)
{
	//session->u32TimeStamp=u32TimeStamp;
	switch(session->emPayload)
	{
		case _h264:
			//return SendNalu264(session, pData, s32DataSize);
			session->u32TimeStamp=u32TimeStamp*(90);
			return SendOneNalu(session, pData, s32DataSize);
		case _g711:
			session->u32TimeStamp=u32TimeStamp*8;
			//return SendNalu711(session, pData, s32DataSize);
			return SendNalu711(session, pData, s32DataSize);
		default:return -1;
		
	}
	return 0;

}


#if 1
int SendDataFully(int fd,char *pszData, int iLen)
{
	int nwritten,r,iTimes=0;

    nwritten = 0;
    while ( nwritten < iLen )
    {

        r = send( fd, pszData + nwritten, iLen - nwritten,MSG_NOSIGNAL|MSG_DONTWAIT);
        if ( r < 0 && ( errno == EINTR || errno == EAGAIN ) )
        {
            msleep(10);
			//printf("wait again 111.....\n");
			if(iTimes++>200)
			{
				perror("SendDataFully  error\n");
				return -1;
			}
            continue;
        }
		
        if ( r < 0 )
        {
			perror("SendDataFully  error");
            return r;
		}
#if 0
        if ( r == 0 )
            break;
#endif
        nwritten += r;
    }

    return 0;
}
#else


int SendDataFully(int fd,char *pszData,unsigned int iLen)
{
	int iRetLen;
	iRetLen = send(fd, pszData, iLen, 0);
	if (iRetLen != iLen)
	{
		perror("SendDataFully  error\n");
		//PRINTF("hLSetRecordParamRequest() send(response) errno %d\n", errno);
		return -1;
	}


    return 0;
}


#endif




int RTP_sendto(RTP_session *session, rtp_protos proto,  char *pkt, ssize_t pkt_size)
{
    int sent = -1;
    int  fd = (proto == rtp_proto) ? session->transport.rtp_fd: session->transport.rtcp_fd_out;

    struct sockaddr *peer = (proto == rtp_proto) ? &(session->transport.u.udp.rtp_peer) : &(session->transport.u.udp.rtcp_out_peer);

    socklen_t peer_len = (proto == rtp_proto) ? sizeof(session->transport.u.udp.rtp_peer) : sizeof(session->transport.u.udp.rtcp_out_peer);

    switch (session->transport.type)
    {
    case RTP_rtp_avp:

       // sent = sendto(fd, pkt, pkt_size, 0, peer, peer_len);
		//printf("send fd=%d\n",fd);
      //  break;
		  if (fd > 0)
		  {
            return SendDataFully(fd, pkt, pkt_size);
		  }
        break;

    case RTP_rtp_avp_tcp:
    {
 		static   char tcp_pkt[1600];
        unsigned short *intlvd_ch = (unsigned short *)&tcp_pkt[2];
		//printf("pkt_size + 4=%d\n",pkt_size + 4);
        tcp_pkt[0] = '$';
		
        tcp_pkt[1] = (proto == rtp_proto) ? session->transport.u.tcp.interleaved.RTP : session->transport.u.tcp.interleaved.RTCP;
		printf("session type=%d tcp_pkt[1]=%d pkt_size=%d\n ",session->emPayload,tcp_pkt[1],pkt_size);
		*intlvd_ch = htons((unsigned short)pkt_size);
        memcpy(tcp_pkt + 4, pkt, pkt_size);

        if (fd > 0)
            return SendDataFully(fd, tcp_pkt, pkt_size + 4);
        break;
    }

    default:
        break;
    }
	printf("sent=%d.....................................\n",sent);
    return sent;
}


RTP_session *RTP_session_destroy(RTP_session *session)
{
    RTP_session *next = session->next;

    switch (session->transport.type)
    {
    case RTP_rtp_avp:
        // we must close socket only if we use udp, because for interleaved tcp
        // we use rtsp that must not be closed here.
        close(session->transport.rtp_fd);
        close(session->transport.rtcp_fd_in);
        close(session->transport.rtcp_fd_out);
        break;

    case RTP_rtp_avp_tcp:
        session->transport.rtp_fd = session->transport.rtcp_fd_out = -1;
        break;

    default:
        break;
    }

    free(session);

    return next;
}


