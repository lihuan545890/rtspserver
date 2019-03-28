#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <errno.h>
#include <string.h>
#include <netinet/in.h>


#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "fcntl.h"
#include "limits.h"
#include "sys/types.h"
#include "sys/stat.h"
#include "arpa/inet.h"
#include "sys/select.h"
#include "sys/time.h"
#include "time.h"
#include "unistd.h"
#include "signal.h"
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "rtp.h"
#include "rtsp.h"
//#include "rtcp.h"
#include "schedule.h"
#include "log.h"


#define MAX_VIDEO_STREAM  2 
#define SDP_EL "\r\n"

#define RTSP_RTP_AVP "RTP/AVP"

#if 0
static int g_s32Maxfd = 0;//最大轮询id号
static int iMaxPortNum=0;
#endif

#if 0

static uint32_t s_u32StartPort=0;
static uint32_t s_uPortPool[50];//RTP端口

#endif




char *sock_ntop_host(const struct sockaddr *sa, socklen_t salen, char *str, size_t len)
{
	switch (sa->sa_family) {
	case AF_INET:
	{
		struct sockaddr_in	*sin = (struct sockaddr_in *) sa;

		if (inet_ntop(AF_INET, &sin->sin_addr, str, len) == NULL)
			return(NULL);
		return(str);
	}

	default:
		PRINT_DBG(str, len, "sock_ntop_host: unknown AF_xxx: %d, len %d",
				 sa->sa_family, salen);
		return(str);
	}
    return (NULL);
}

int tcp_accept(int fd)
{
    int f;
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    memset(&addr,0,sizeof(addr));
    addrlen=sizeof(addr);

    /*接收连接，创建一个新的socket,返回其描述符*/
    f = accept (fd, (struct sockaddr *)&addr, &addrlen);

    return f;
}

void tcp_close(int s)
{
    close(s);
}

int tcp_connect(unsigned short port, char *addr)
{
	int f;
	int on=1;
	int one = 1;/*used to set SO_KEEPALIVE*/

	struct sockaddr_in s;
	int v = 1;
	if ((f = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0) {
		fprintf(stderr, "socket() error in tcp_connect.\n" );
		return -1;
	}
	setsockopt(f, SOL_SOCKET, SO_REUSEADDR, (char *) &v, sizeof(int));
	s.sin_family = AF_INET;
	s.sin_addr.s_addr = inet_addr(addr);//htonl(addr);
	s.sin_port = htons(port);
	// set to non-blocking
	if (ioctl(f, FIONBIO, &on) < 0) {
		fprintf(stderr,"ioctl() error in tcp_connect.\n" );
		return -1;
	}
	if (connect(f,(struct sockaddr*)&s, sizeof(s)) < 0) {
		fprintf(stderr,"connect() error in tcp_connect.\n" );
		return -1;
	}
	if(setsockopt(f, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one))<0){
		fprintf(stderr,"setsockopt() SO_KEEPALIVE error in tcp_connect.\n" );
		return -1;
	}
	return f;
}

int tcp_listen(unsigned short port)
{
    int f;
    int on=1;

    struct sockaddr_in s;
    int v = 1;

    /*创建套接字*/
    if ((f = socket(AF_INET, SOCK_STREAM, 0))<0)
    {
        fprintf(stderr, "socket() error in tcp_listen.\n" );
        return -1;
    }

    /*设置socket的可选参数*/
    setsockopt(f, SOL_SOCKET, SO_REUSEADDR, (char *) &v, sizeof(int));

    s.sin_family = AF_INET;
    s.sin_addr.s_addr = htonl(INADDR_ANY);
    s.sin_port = htons(port);

    /*绑定socket*/
    if (bind (f, (struct sockaddr *)&s, sizeof (s)))
    {
    	PRINT_DBG("bind() error in tcp_listen" );
		tcp_close(f);
        return -1;
    }

    //设置为非阻塞方式
    if (ioctl(f, FIONBIO, &on) < 0)
    {
    	 PRINT_DBG("ioctl() error in tcp_listen.\n" );
		 tcp_close(f);
        return -1;
    }

    /*监听*/
    if (listen(f, SOMAXCONN) < 0)
    {
    	 PRINT_DBG("listen() error in tcp_listen.\n" );
		 tcp_close(f);
        return -1;
    }
	
    return f;
}

int tcp_read(int fd, void *buffer, int nbytes, struct sockaddr *Addr)
{
    int n;


    n=recv(fd, buffer, nbytes, 0);

    if(n>0)
    {
#if 0
		socklen_t Addrlen = sizeof(struct sockaddr);
		char addr_str[128];

    	//获取对方IP信息
        if( getpeername(fd, Addr, &Addrlen) < 0 )
        {
            PRINT_DBG("getpeername error\n");
        }
        else
        {
        	//打印出IP和port
         	PRINT_DBG("RTSP <<%s:%d\n", sock_ntop_host(Addr, Addrlen, addr_str, sizeof(addr_str)),ntohs(((struct sockaddr_in *)Addr)->sin_port));
        }
#endif
    }

    return n;
}



int tcp_write(int connectSocketId, char *dataBuf, int dataSize)
{
	int 	actDataSize;

	//发送数据
	while(dataSize > 0)
	{
		actDataSize = send(connectSocketId, dataBuf, dataSize, 0);

		if(actDataSize<=0)
			break;

		dataBuf  += actDataSize;
		dataSize -= actDataSize;
	}

	if(dataSize > 0)
	{
		printf("Send Data error\n");
		return -1;
	}

	return 0;
}


int udp_open(unsigned short port, struct sockaddr *s_addr, int  *fd)
{
    struct sockaddr_in s;
    int on = 1;

    if (!*fd)
    {
        if ((*fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        {
           // fnc_log(FNC_LOG_ERR, "socket() error in udp_open.\n" );
            return ERR_GENERIC;
        }
        // set to non-blocking
        if (ioctl(*fd, FIONBIO, &on) < 0)
        {
            //fnc_log(FNC_LOG_ERR, "ioctl() error in udp_open.\n" );
            return ERR_GENERIC;
        }
    }

    s.sin_family = AF_INET;
    s.sin_addr.s_addr = htonl(INADDR_ANY);
    s.sin_port =  htons(port);
    if (bind (*fd, (struct sockaddr *)&s, sizeof (s)))
    {
       // fnc_log(FNC_LOG_ERR, "bind() error in udp_open.\n" );
        return ERR_GENERIC;
    }
    *s_addr = *((struct sockaddr *)&s);

    return ERR_NOERROR;
}


int udp_connect(unsigned short to_port, struct sockaddr *s_addr, int addr, int *fd)
{
    struct sockaddr_in s;
    int on = 1; //,v=1;
    if (!*fd)
    {
        if ((*fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        {
           // fnc_log(FNC_LOG_ERR, "socket() error in udp_connect.\n" );
            return ERR_GENERIC;
        }
        /*set to non-blocking*/
        if (ioctl(*fd, FIONBIO, &on) < 0)
        {
           // fnc_log(FNC_LOG_ERR, "ioctl() error in udp_connect.\n" );
            return ERR_GENERIC;
        }
    }
    s.sin_family = AF_INET;
    s.sin_addr.s_addr = addr;
    s.sin_port = htons(to_port);
    if (connect(*fd, (struct sockaddr *)&s, sizeof(s)) < 0)
    {
       // fnc_log(FNC_LOG_ERR, "connect() error in udp_connect.\n" );
        return ERR_GENERIC;
    }
    *s_addr = *((struct sockaddr *)&s);

    return ERR_NOERROR;
}

//把需要发送的信息放入rtsp.out_buffer中
int bwrite(char *buffer, unsigned short len, RTSP_buffer * rtsp)
{
    /*检查是否有缓冲溢出*/
    if ((rtsp->out_size + len) > (int) sizeof(rtsp->out_buffer))
    {
    	fprintf(stderr,"bwrite(): not enough free space in out message buffer.\n");
        return ERR_ALLOC;
    }
    /*填充数据*/
    memcpy(&(rtsp->out_buffer[rtsp->out_size]), buffer, len);
    rtsp->out_buffer[rtsp->out_size + len] = '\0';
    rtsp->out_size += len;
	
    return ERR_NOERROR;
}

int send_reply(int err, char *addon, RTSP_buffer * rtsp)
{
    unsigned int len;
    char *b;
    int res;

    if (addon != NULL)
    {
        len = 256 + strlen(addon);
    }
    else
    {
        len = 256;
    }

    /*分配空间*/
    b = (char *) malloc(len);
    if (b == NULL)
    {
        PRINT_DBG("send_reply(): memory allocation error.\n");
        return ERR_ALLOC;
    }
    memset(b, 0, sizeof(b));
    /*按照协议格式填充数据*/
    sprintf(b, "%s %d %s"RTSP_EL"CSeq: %d"RTSP_EL, RTSP_VER, err, get_stat(err), rtsp->rtsp_cseq);
    strcat(b, RTSP_EL);

    /*将数据写入到缓冲区中*/
    res = bwrite(b, (unsigned short) strlen(b), rtsp);
    //释放空间
    free(b);

    return res;
}




//由错误码返回错误信息
const char *get_stat(int err)
{
    struct {
        const char *token;
        int code;
    } status[] = {
        {
        "Continue", 100}, {
        "OK", 200}, {
        "Created", 201}, {
        "Accepted", 202}, {
        "Non-Authoritative Information", 203}, {
        "No Content", 204}, {
        "Reset Content", 205}, {
        "Partial Content", 206}, {
        "Multiple Choices", 300}, {
        "Moved Permanently", 301}, {
        "Moved Temporarily", 302}, {
        "Bad Request", 400}, {
        "Unauthorized", 401}, {
        "Payment Required", 402}, {
        "Forbidden", 403}, {
        "Not Found", 404}, {
        "Method Not Allowed", 405}, {
        "Not Acceptable", 406}, {
        "Proxy Authentication Required", 407}, {
        "Request Time-out", 408}, {
        "Conflict", 409}, {
        "Gone", 410}, {
        "Length Required", 411}, {
        "Precondition Failed", 412}, {
        "Request Entity Too Large", 413}, {
        "Request-URI Too Large", 414}, {
        "Unsupported Media Type", 415}, {
        "Bad Extension", 420}, {
        "Invalid Parameter", 450}, {
        "Parameter Not Understood", 451}, {
        "Conference Not Found", 452}, {
        "Not Enough Bandwidth", 453}, {
        "Session Not Found", 454}, {
        "Method Not Valid In This State", 455}, {
        "Header Field Not Valid for Resource", 456}, {
        "Invalid Range", 457}, {
        "Parameter Is Read-Only", 458}, {
        "Unsupported transport", 461}, {
        "Internal Server Error", 500}, {
        "Not Implemented", 501}, {
        "Bad Gateway", 502}, {
        "Service Unavailable", 503}, {
        "Gateway Time-out", 504}, {
        "RTSP Version Not Supported", 505}, {
        "Option not supported", 551}, {
        "Extended Error:", 911}, {
        NULL, -1}
    };

    int i;
    for (i = 0; status[i].code != err && status[i].code != -1; ++i);

    return status[i].token;
}



//为缓冲分配空间
void RTSP_initserver(RTSP_buffer *rtsp, int fd)
{

	int			keepAlive = 1;
    int			keepIdle = 3;
    int			keepInterval = 1;
    int			keepCount = 5;
	int nFlag = 1;

	
    rtsp->fd = fd;
	rtsp->iNeedClose=0;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void *)&nFlag, sizeof(int));

	if (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepAlive, sizeof(int)) == -1)
    {
        //PRINTF("setsockopt() SO_KEEPALIVE failure\n");
    }

    if (setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, (void *)&keepIdle, sizeof(int)) == -1)
    {
        //PRINTF("setsockopt() SO_KEEPIDLE failure\n");
    }

    if (setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, (void *)&keepInterval, sizeof(int)) == -1)
    {
        //PRINTF("setsockopt() SO_KEEPINTVL failure\n");
    }

    if (setsockopt(fd, SOL_TCP, TCP_KEEPCNT, (void *)&keepCount, sizeof(int)) == -1)
    {
        //PRINTF("setsockopt() SO_KEEPCNT failure\n");
    }
	
    rtsp->session_list = (RTSP_session *) calloc(1, sizeof(RTSP_session));
    rtsp->session_list->session_id = -1;
}




//为RTP准备两个端口

int port_isfree (int port)  
{  
        struct sockaddr_in sin;  
        int                sock = -1;  
        int                ret = 0;  
        int                opt = 0;  
    
        memset (&sin, 0, sizeof (sin));  
        sin.sin_family = PF_INET;  
        sin.sin_port = htons (port);  
  
        sock = socket (PF_INET, SOCK_STREAM, 0);
		
        if (sock == -1)
        {
            return -1;  
        }
        ret = setsockopt (sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof (opt));  
        ret = bind (sock, (struct sockaddr *)&sin, sizeof (sin)); 
		
        close (sock);  
  
        return (ret == 0) ? 1 : 0;  
		
} 

int RTP_get_port_pair(port_pair *pair)
{
    int i,iStart=0;
	int RtpPort=0;
	
	iStart=schedule_GetCount();
	if(iStart<0)
	{
		iStart=0;
	}
	
	for(i=iStart;i<100;i++)
	{
		RtpPort=50000+iStart*2;
		if(port_isfree(RtpPort) && port_isfree(RtpPort+1))
		{
			pair->RTP=RtpPort;
			pair->RTCP=RtpPort+1;
			return 0;
		}
	}
	
    return ERR_GENERIC;
}


#if 0


void RTP_port_pool_init(int port,int iMax)
{
    int i;
    s_u32StartPort = port;
    for (i=0; i<iMax; ++i)
    {
    	s_uPortPool[i] = i+s_u32StartPort;
    }
	
	iMaxPortNum=iMax;
}
#endif


void AddClient(RTSP_buffer **ppRtspList, int fd)
{
    RTSP_buffer *pRtsp=NULL,*pRtspNew=NULL;



    //在链表头部插入第一个元素
    if (*ppRtspList==NULL)
    {
        /*分配空间*/
        if ( !(*ppRtspList=(RTSP_buffer*)calloc(1,sizeof(RTSP_buffer)) ) )
        {
            fprintf(stderr,"alloc memory error %s,%i\n", __FILE__, __LINE__);
            return;
        }
        pRtsp = *ppRtspList;
    }
    else
    {
    	//向链表中插入新的元素
        for (pRtsp=*ppRtspList; pRtsp!=NULL; pRtsp=pRtsp->next)
        {
        	pRtspNew=pRtsp;
        }
        /*在链表尾部插入*/
        if (pRtspNew!=NULL)
        {
        	if ( !(pRtspNew->next=(RTSP_buffer *)calloc(1,sizeof(RTSP_buffer)) ) )
            {
                fprintf(stderr, "error calloc %s,%i\n", __FILE__, __LINE__);
                return;
            }
            pRtsp=pRtspNew->next;
            pRtsp->next=NULL;
        }
    }

#if 0
    //设置最大轮询id号
    if(g_s32Maxfd < fd)
    {
    	g_s32Maxfd = fd;
    }
#endif

    /*初始化新添加的客户端*/
    RTSP_initserver(pRtsp,fd);
   // fprintf(stderr,"Incoming RTSP connection accepted on socket: %d\n",pRtsp->fd);

}

/*根据缓冲区的内容，填充后边两个长度数据,检查缓冲区中消息的完整性
 * return -1 on ERROR
 * return RTSP_not_full (0) if a full RTSP message is NOT present in the in_buffer yet.
 * return RTSP_method_rcvd (1) if a full RTSP message is present in the in_buffer and is
 *                     ready to be handled.
 * return RTSP_interlvd_rcvd (2) if a complete RTP/RTCP interleaved packet is present.
 * terminate on really ugly cases.
 */
int RTSP_full_msg_rcvd(RTSP_buffer *rtsp, int *hdr_len, int *body_len)
{
    int eomh;    /* end of message header found */
    int mb;       /* message body exists */
    int tc;         /* terminator count */
    int ws;        /* white space */
    unsigned int ml;              /* total message length including any message body */
    int bl;                           /* message body length */
    char c;                         /* character */
    int control;
    char *p;

    /*是否存在交叉存取的二进制rtp/rtcp数据包，参考RFC2326-10.12*/
    if (rtsp->in_buffer[0] == '$')
    {
    	uint16_t *intlvd_len = (uint16_t *)&rtsp->in_buffer[2];   /*跳过通道标志符*/

        /*转化为主机字节序，因为长度是网络字节序*/
        if ( (bl = ntohs(*intlvd_len)) <= rtsp->in_size)
        {
        	//fprintf(stderr,"Interleaved RTP or RTCP packet arrived (len: %hu).\n", bl);
            if (hdr_len)
                *hdr_len = 4;
            if (body_len)
                *body_len = bl;
			//printf("get a full rtcp message\n");
            return RTSP_interlvd_rcvd;
        }
        else
        {
            /*缓冲区不能完全存放数据*/
            //fprintf(stderr,"Non-complete Interleaved RTP or RTCP packet arrived.\n");
            return RTSP_not_full;
        }

    }


    eomh = mb = ml = bl = 0;
    while (ml <= rtsp->in_size)
    {
        /* look for eol. */
        /*计算不包含回车、换行在内的所有字符数*/
        control = strcspn(&(rtsp->in_buffer[ml]), "\r\n");
        if(control > 0)
            ml += control;
        else
            return ERR_GENERIC;

        /* haven't received the entire message yet. */
        if (ml > rtsp->in_size)
            return RTSP_not_full;


        /* 处理终结符，判读是否是消息头的结束*/
        tc = ws = 0;
        while (!eomh && ((ml + tc + ws) < rtsp->in_size))
        {
            c = rtsp->in_buffer[ml + tc + ws];
            /*统计回车换行*/
            if (c == '\r' || c == '\n')
                tc++;
            else if ((tc < 3) && ((c == ' ') || (c == '\t')))
            {
                ws++;                 /*回车、换行之间的空格或者TAB，也是可以接受的 */
            }
            else
            {
            	break;
            }
        }

        /*
         *一对回车、换行符仅仅被统计为一个行终结符
         * 双行可以被接受，并将其认为是消息头的结束标识
         * 这与RFC2068中的描述一致，参考rfc2068 19.3
         *否则，对所有的HTTP/1.1兼容协议消息元素来说，
         *回车、换行被认为是合法的行终结符
         */

        /* must be the end of the message header */
        if ((tc > 2) || ((tc == 2) && (rtsp->in_buffer[ml] == rtsp->in_buffer[ml + 1])))
            eomh = 1;
        ml += tc + ws;

        if (eomh)
        {
            ml += bl;   /* 加入消息体长度 */
            if (ml <= rtsp->in_size)
            	break;  /* all done finding the end of the message. */
        }

        if (ml >= rtsp->in_size)
            return RTSP_not_full;   /* 还没有完全接收消息 */

        /*检查每一行的第一个记号，确定是否有消息体存在 */
        if (!mb)
        {
            /* content length token not yet encountered. */
            if (!strncmp(&(rtsp->in_buffer[ml]), HDR_CONTENTLENGTH, strlen(HDR_CONTENTLENGTH)))
            {
                mb = 1;                        /* 存在消息体. */
                ml += strlen(HDR_CONTENTLENGTH);

                /*跳过:和空格，找到长度字段*/
                while (ml < rtsp->in_size)
                {
                    c = rtsp->in_buffer[ml];
                    if ((c == ':') || (c == ' '))
                        ml++;
                    else
                        break;
                }
                //Content-Length:后面是消息体长度值
                if (sscanf(&(rtsp->in_buffer[ml]), "%d", &bl) != 1)
                {
                    //fprintf(stderr,"RTSP_full_msg_rcvd(): Invalid ContentLength encountered in message.\n");
                    return ERR_GENERIC;
                }
            }
        }
    }

    if (hdr_len)
        *hdr_len = ml - bl;

    if (body_len)
    {
    /*
     * go through any trailing nulls.  Some servers send null terminated strings
     * following the body part of the message.  It is probably not strictly
     * legal when the null byte is not included in the Content-Length count.
     * However, it is tolerated here.
     * 减去可能存在的\0，它没有被计算在Content-Length中
     */
        for (tc = rtsp->in_size - ml, p = &(rtsp->in_buffer[ml]); tc && (*p == '\0'); p++, bl++, tc--);
            *body_len = bl;
    }

    return RTSP_method_rcvd;
}

/*
 * return	0 是客户端发送的请求
 *			1 是服务器返回的响应
 */
int RTSP_valid_response_msg(unsigned short *status, RTSP_buffer * rtsp)
{
    char ver[32], trash[15];
    unsigned int stat;
    unsigned int seq;
    int pcnt;                   /* parameter count */

    /* assuming "stat" may not be zero (probably faulty) */
    stat = 0;

    /*从消息中填充数据*/
    pcnt = sscanf(rtsp->in_buffer, " %31s %u %s %s %u\n%*255s ", ver, &stat, trash, trash, &seq);

    /* 通过起始字符，检查信息是客户端发送的请求还是服务器做出的响应*/
    /* C->S CMD rtsp://IP:port/suffix RTSP/1.0\r\n			|head
     * 		CSeq: 1 \r\n									|
     * 		Content_Length:**								|body
     * S->C RTSP/1.0 200 OK\r\n
     * 		CSeq: 1\r\n
     * 		Date:....
      */
    if (strncmp(ver, "RTSP/", 5))
        return 0;   /*不是响应消息，是客户端请求消息，返回*/

    /*确信至少存在版本、状态码、序列号*/
    if (pcnt < 3 || stat == 0)
        return 0;            /* 表示不是一个响应消息   */

    /*如果版本不兼容，在此处增加码来拒绝该消息*/

    /*检查回复消息中的序列号是否合法*/
    if (rtsp->rtsp_cseq != seq + 1)
    {
        fprintf(stderr,"Invalid sequence number returned in response.\n");
        return ERR_GENERIC;    /*序列号错误，返回*/
    }

    *status = stat;
    return 1;
}

//返回请求方法类型，出错返回-1
int RTSP_validate_method(RTSP_buffer * pRtsp)
{
    char method[32];
    char object[256];
    unsigned int seq;
    int pcnt;   /* parameter count */
    int mid = ERR_GENERIC;
	char *ptr=NULL;

    *method = *object = '\0';
    seq = 0;

    /*按照请求消息的格式解析消息的第一行*/
    //if ( (pcnt = sscanf(pRtsp->in_buffer, " %31s %255s %31s\n%15s %u ", method, object, ver, hdr, &seq)) != 5)
	if ( (pcnt = sscanf(pRtsp->in_buffer, "%31s ", method)) != 1)
	{   
		 fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
		return ERR_GENERIC;
	}

    /*如果没有头标记，则错误*/
    if ( (ptr=strstr(pRtsp->in_buffer, HDR_CSEQ))==NULL )
    {
		 fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
        return ERR_GENERIC;
	}
	seq=atoi(ptr+5);

    /*根据不同的方法，返回响应的方法ID*/
    if (strcmp(method, RTSP_METHOD_DESCRIBE) == 0) {
        mid = RTSP_ID_DESCRIBE;
    }
    if (strcmp(method, RTSP_METHOD_ANNOUNCE) == 0) {
        mid = RTSP_ID_ANNOUNCE;
    }
    if (strcmp(method, RTSP_METHOD_GET_PARAMETERS) == 0) {
        mid = RTSP_ID_GET_PARAMETERS;
    }
    if (strcmp(method, RTSP_METHOD_OPTIONS) == 0) {
        mid = RTSP_ID_OPTIONS;
    }
    if (strcmp(method, RTSP_METHOD_PAUSE) == 0) {
        mid = RTSP_ID_PAUSE;
    }
    if (strcmp(method, RTSP_METHOD_PLAY) == 0) {
        mid = RTSP_ID_PLAY;
    }
    if (strcmp(method, RTSP_METHOD_RECORD) == 0) {
        mid = RTSP_ID_RECORD;
    }
    if (strcmp(method, RTSP_METHOD_REDIRECT) == 0) {
        mid = RTSP_ID_REDIRECT;
    }
    if (strcmp(method, RTSP_METHOD_SETUP) == 0) {
        mid = RTSP_ID_SETUP;
    }
    if (strcmp(method, RTSP_METHOD_SET_PARAMETER) == 0) {
        mid = RTSP_ID_SET_PARAMETER;
    }
    if (strcmp(method, RTSP_METHOD_TEARDOWN) == 0) {
        mid = RTSP_ID_TEARDOWN;
    }

    /*设置当前方法的请求序列号*/
    pRtsp->rtsp_cseq = seq;
    return mid;
}

//解析URL中的port端口和文件名称
int ParseUrl(const char *pUrl, char *pServer, unsigned short *port, char *pFileName, size_t FileNameLen)
{
	/* expects format [rtsp://server[:port/]]filename RTSP/1.0*/

	int s32NoValUrl;

    /*拷贝URL */
    char *pFull = (char *)malloc(strlen(pUrl) + 1);
    strcpy(pFull, pUrl);

    /*检查前缀是否正确*/
    if (strncmp(pFull, "rtsp://", 7) == 0)
    {
        char *pSuffix;

        //找到/ 它之后是文件名
        if((pSuffix = strchr(&pFull[7], '/')) != NULL)
        {
        	char *pPort;
        	char pSubPort[128];
        	//判断是否有端口
        	pPort=strchr(pFull, ':');
        	if(pPort != NULL)
        	{
        		strncpy(pSubPort, pPort+1, pSuffix-pPort-1);
        		pSubPort[pSuffix-pPort-1] = '\0';
        		*port = (unsigned short) atol(pSubPort);
        	}
        	else
        	{
        		*port = 554;
        	}
        	pSuffix++;
        	//跳过空格或者制表符
        	while(*pSuffix == ' '||*pSuffix == '\t')
        	{
        		pSuffix++;
        	}
        	//拷贝文件名
        	strcpy(pFileName, pSuffix);
        	s32NoValUrl = 0;
        }
        else
        {
        	*port = 554;
        	*pFileName = '\0';
        	s32NoValUrl = 1;
        }
    }else
    {
    	*pFileName = '\0';
    	s32NoValUrl = 1;
    }
    //释放空间
    free(pFull);
    return s32NoValUrl;
}

//把当前时间作为session号
char *GetSdpId(char *buffer)
{
	time_t t;
    buffer[0]='\0';
    t = time(NULL);
    sprintf(buffer,"%.0f",(float)t+2208988800U);    /*获得NPT时间*/
    return buffer;
}

#if 0
void GetSdpDescr(RTSP_buffer * pRtsp, char *pDescr, char *s8Str)
{
	char const* const SdpPrefixFmt =
			"v=0\r\n"	//版本信息
			"o=- %s %s IN IP4 %s\r\n" //<用户名><会话id><版本>//<网络类型><地址类型><地址>
			"c=IN IP4 0.0.0.0\r\n"		//c=<网络信息><地址信息><连接地址>对ip4为0.0.0.0
			"s=RTSP Session\r\n"		//会话名session id
//			"i=%s\r\n"		//会话信息
			"t=0 0\r\n"		//<开始时间><结束时间>
			"m=video %s RTP/AVP 96\r\n"	//<媒体格式><端口><传送><格式列表,即媒体净荷类型> m=video 5858 RTP/AVP 96
			"a=rtpmap:96 %s/90000\r\n\r\n";		//a=rtpmap:<净荷类型><编码名>/<时钟速率> 	a=rtpmap:96 H264/90000

	struct ifreq stIfr;
	char pSdpId[128];

	//获取本机地址
#if 1
    strcpy(stIfr.ifr_name, "eth0");
    if(ioctl(pRtsp->fd, SIOCGIFADDR, &stIfr) < 0)
    {
		printf("Failed to get host ip\n");
    }
	
	sock_ntop_host(&stIfr.ifr_addr, sizeof(struct sockaddr), s8Str, 128);
#else
	strncpy(s8Str,"192.168.1.11",128);
#endif

	GetSdpId(pSdpId);

	sprintf(pDescr, SdpPrefixFmt,  pSdpId, pSdpId, s8Str, "0", "H264");

}
#else
#if 0
void GetSdpDescr(RTSP_buffer * pRtsp,int videoIndex, char *pDescr, char *s8Str)
{
	const char * SdpPrefixFmt=
	"v=0\r\n"
	"o=rtsp %s %s IN IP4 0.0.0.0\r\n"
	"s=RTSP Session\r\n"
	"i=rtsp server\r\n"
	"c=IN IP4 0.0.0.0\r\n"
	"t=0 0\r\n"
	"a=control:*\r\n"
	"m=video 0 RTP/AVP 96\r\n"
	"a=rtpmap:96 H264/90000\r\n"
	"a=fmtp:96 %s\r\n"
	"a=framerate:%d\r\n"
	"a=range:npt=now-\r\n"
	"a=control:trackID=0\r\n"
	"m=audio 0 RTP/AVP 8\r\n"
	"a=rtpmap:8 pcma/8000/1\r\n"
	"a=range:npt=now-\r\n"
	"a=control:trackID=1\r\n";


	char pSdpId[128];
	char szVideoArrtBuf[256];
	int  Framerate=0;

	memset(szVideoArrtBuf,0,sizeof(szVideoArrtBuf));

	if(videoIndex>=0&&videoIndex<MAX_VIDEO_STREAM)
	{
		Framerate=g_stHlAllParam.stVideoParam.stVencParam[videoIndex].byFrameRate;
		HL_VideoGetVideoAttr(videoIndex,szVideoArrtBuf);
	}


	strncpy(s8Str,g_stHlAllParam.stNetParam.szLocalIpAddr,128);

	GetSdpId(pSdpId);

	sprintf(pDescr, SdpPrefixFmt,  pSdpId, pSdpId,szVideoArrtBuf,Framerate);
}
#endif

void GetSdpDescr(RTSP_buffer * pRtsp,int videoIndex, char *pDescr, char *s8Str)
{
	const char * SdpPrefixFmt=
	"v=0\r\n"
	"o=rtsp %s %s IN IP4 0.0.0.0\r\n"
	"s=RTSP Session\r\n"
	"i=rtsp server\r\n"
	"c=IN IP4 0.0.0.0\r\n"
	"t=0 0\r\n"
	"a=control:*\r\n"
	"m=video 0 RTP/AVP 96\r\n"
	"a=rtpmap:96 H264/90000\r\n"
	"a=fmtp:96 %s\r\n"
	"a=framerate:%d\r\n"
	"a=range:npt=now-\r\n"
	"a=control:trackID=0\r\n%s";

	char * pszAudioFmt=
	"m=audio 0 RTP/AVP %d\r\n"
	"a=rtpmap:%d %s/8000/1\r\n"
	"a=range:npt=now-\r\n"
	"a=control:trackID=1\r\n";


	char pSdpId[128];
	char szVideoArrtBuf[1024];
	char szAudioBuf[128];
	int  Framerate=0;
    unsigned char   byAudioEnable = 0;
    unsigned char   AudioEncType = 0;
//	unsigned char   byAudioEnable=g_stHLAllParam.stAudioParam.stAencParam[0].byEnable;
//	unsigned char   AudioEncType=g_stHLAllParam.stAudioParam.stAencParam[0].byEncType;
    char szAudioStr[8]={0};
	switch(AudioEncType)
	{
	/*	case AUDIO_TYPE_G711U:
			AudioEncType=0;
			sprintf(szAudioStr,"%s","pcmu");
			break;
		case AUDIO_TYPE_G711A:
			sprintf(szAudioStr,"%s","pcma");
			AudioEncType=8;
			break;*/
		default:
			AudioEncType=8;
			sprintf(szAudioStr,"%s","pcma");
	}

	memset(szVideoArrtBuf,0,sizeof(szVideoArrtBuf));
	sprintf(szVideoArrtBuf,"");
	GetVideoAttr(szVideoArrtBuf);
/*	if(videoIndex>=0&&videoIndex<MAX_VIDEO_STREAM)
	{
		Framerate=g_stHLAllParam.stVideoParam.stVencParam[videoIndex].byFrameRate;
		HL_VideoGetVideoAttr(videoIndex,szVideoArrtBuf);
	}
*/
	Framerate = 30;
/*
	strncpy(s8Str,g_stHLAllParam.stNetParam.szLocalIpAddr,128);
*/
	GetSdpId(pSdpId);

	if(byAudioEnable)
	{
		sprintf(szAudioBuf,pszAudioFmt,AudioEncType,AudioEncType,szAudioStr);
	}
	else
	{
		sprintf(szAudioBuf,"");
	}
	
	sprintf(s8Str, "%s", "192.168.199.128");
//	sprintf(szVideoArrtBuf, "%s", "profile-level-id=42002A; sprop-parameter-sets=,; packetization-mode=1");
	sprintf(pDescr, SdpPrefixFmt,  pSdpId, pSdpId,szVideoArrtBuf,Framerate,szAudioBuf);


}

#endif






/*添加时间戳*/
void add_time_stamp(char *b, int crlf)
{
    struct tm *t;
    time_t now;

    /*
    * concatenates a null terminated string with a
    * time stamp in the format of "Date: 23 Jan 1997 15:35:06 GMT"
    */
    now = time(NULL);
    t = gmtime(&now);
    //输出时间格式：Date: Fri, 15 Jul 2011 09:23:26 GMT
    strftime(b + strlen(b), 38, "Date: %a, %d %b %Y %H:%M:%S GMT"RTSP_EL, t);

    //是否是消息结束，添加回车换行符
    if (crlf)
        strcat(b, "\r\n");	/* add a message header terminator (CRLF) */
}

int SendDescribeReply(RTSP_buffer * rtsp, char *object, char *descr, char *s8Str)
{
    char *pMsgBuf;            /* 用于获取响应缓冲指针*/
    int s32MbLen;

    /* 分配空间，处理内部错误*/
    s32MbLen = 2048;
    pMsgBuf = (char *)malloc(s32MbLen);
    if (!pMsgBuf)
    {
        fprintf(stderr,"send_describe_reply(): unable to allocate memory\n");
        send_reply(500, 0, rtsp);    /* internal server error */
        if (pMsgBuf)
        {
            free(pMsgBuf);
        }
        return ERR_ALLOC;
    }

    /*构造describe消息串*/
    sprintf(pMsgBuf, "%s %d %s"RTSP_EL"CSeq: %d"RTSP_EL"Server: %s/%s"RTSP_EL, RTSP_VER, 200, get_stat(200), rtsp->rtsp_cseq, PACKAGE, VERSION);
    add_time_stamp(pMsgBuf, 0);                 /*添加时间戳*/

	strcat(pMsgBuf, "Content-Type: application/sdp"RTSP_EL);   /*实体头，表示实体类型*/

    /*用于解析实体内相对url的 绝对url*/
    sprintf(pMsgBuf + strlen(pMsgBuf), "Content-Base: rtsp://%s/%s/"RTSP_EL, s8Str, object);
    sprintf(pMsgBuf + strlen(pMsgBuf), "Content-Length: %d"RTSP_EL, strlen(descr)); /*消息体的长度*/
    strcat(pMsgBuf, RTSP_EL);

    /*消息头结束*/

    /*加上消息体*/
    strcat(pMsgBuf, descr);    /*describe消息*/
    /*向缓冲区中填充数据*/
    bwrite(pMsgBuf, (unsigned short) strlen(pMsgBuf), rtsp);

    free(pMsgBuf);

    return ERR_NOERROR;
}




int RtspVerifyUrl(int *index,const char *pszRecv)
{
	//rtsp://192.168.8.123/1?admin:admin
	//rtsp://192.168.8.123/1?user=admin&pwd=admin
	
	char *pos1,*pos2;
	char szTemp[48];
	char szUser[16],szPass[16];
	PRINT_DBG("pszRecv=%s\n",pszRecv);
	
	if((pos1=strchr(pszRecv,'?'))!=NULL)
	{
		*index=1;
		if(*(pos1-1)=='1')
		{
			*index=0;
		}
		strncpy(szTemp,pos1+1,sizeof(szTemp));

		if((pos2=strchr(szTemp,'&'))!=NULL)
		{
			*pos2='\0';
			strncpy(szUser,szTemp+5,sizeof(szUser));
			pos2++;
			PRINT_DBG("szUser=<%s>\n",szUser);
			if((pos1=strchr(pos2,' '))!=NULL)
			{
				*pos1='\0';
				if((pos1=strchr(pos2,'/'))!=NULL)
				{
					*pos1='\0';
				}
				strncpy(szPass,pos2+4,sizeof(szPass));
				PRINT_DBG("szPass=<%s>\n",szPass);
				return 1;
			}
		}
		else if((pos2=strchr(szTemp,':'))!=NULL)
		{
			//printf("I found : here\n");
			*pos2='\0';
			strncpy(szUser,szTemp,sizeof(szUser));
			printf("szUser=<%s>\n",szUser);
			pos2++;
			if((pos1=strchr(pos2,' '))!=NULL)
			{
				*pos1='\0';
				if((pos1=strchr(pos2,'/'))!=NULL)
				{
					*pos1='\0';
				}
				strncpy(szPass,pos2,sizeof(szUser));
				printf("szPass=<%s>\n",szPass);

				return 1;
			}
		}
			
	}

	return 1;

}




//describe处理
int RTSP_describe(RTSP_buffer * pRtsp)
{
	char object[255], trash[255];
	char *p;
	unsigned short port;
	char s8Url[255];
	char s8Descr[MAX_DESCR_LENGTH];
	char server[128];
	char s8Str[128];
	int index;

	/*根据收到的请求请求消息，跳过方法名，分离出URL*/
	if (!sscanf(pRtsp->in_buffer, " %*s %254s ", s8Url))
	{
		fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
		send_reply(400, 0, pRtsp);                			/* bad request */
		return ERR_NOERROR;
	}

	/*验证URL */
	switch (ParseUrl(s8Url, server, &port, object, sizeof(object)))
	{
		case 1: /*请求错误*/
			fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
			send_reply(400, 0, pRtsp);
			return ERR_NOERROR;
			break;

		case -1: /*内部错误*/
			fprintf(stderr,"url error while parsing !\n");
			send_reply(500, 0, pRtsp);
			return ERR_NOERROR;
			break;

		default:
			break;
	}

	/*取得序列号,并且必须有这个选项*/
	if ((p = strstr(pRtsp->in_buffer, HDR_CSEQ)) == NULL)
	{
		fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
		send_reply(400, 0, pRtsp);  /* Bad Request */
		return ERR_NOERROR;
	}
	else
	{
		if (sscanf(p, "%254s %d", trash, &(pRtsp->rtsp_cseq)) != 2)
		{
			fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
			send_reply(400, 0, pRtsp);   /*请求错误*/
			return ERR_NOERROR;
		}
	}
	
	if(!RtspVerifyUrl(&index,pRtsp->in_buffer))
	{
		fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
		send_reply(400, 0, pRtsp);  /* Bad Request */
		return ERR_NOERROR;
	}

	//获取SDP内容
	GetSdpDescr(pRtsp,index, s8Descr, s8Str);
	//发送Describe响应
	SendDescribeReply(pRtsp, object, s8Descr, s8Str);

	return ERR_NOERROR;
}

//发送options处理后的响应
int send_options_reply(RTSP_buffer * pRtsp, long cseq)
{
    char r[1024];
    sprintf(r, "%s %d %s"RTSP_EL"CSeq: %ld"RTSP_EL, RTSP_VER, 200, get_stat(200), cseq);
    strcat(r, "Public: OPTIONS,DESCRIBE,SETUP,PLAY,TEARDOWN"RTSP_EL);
    strcat(r, RTSP_EL);

    bwrite(r, (unsigned short) strlen(r), pRtsp);

#ifdef RTSP_DEBUG
//	fprintf(stderr ,"SERVER SEND Option Replay: %s\n", r);
#endif

    return ERR_NOERROR;
}



//options处理
int RTSP_options(RTSP_buffer * pRtsp)
{
    char *p;
    char trash[255];
    unsigned int cseq;
   // char method[255], url[255], ver[255];

    /*序列号*/
    if ((p = strstr(pRtsp->in_buffer, HDR_CSEQ)) == NULL)
    {
    	fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
        send_reply(400, 0, pRtsp);/* Bad Request */
        return ERR_NOERROR;
    }
    else
    {
        if (sscanf(p, "%254s %d", trash, &(pRtsp->rtsp_cseq)) != 2)
        {
        	fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
            send_reply(400, 0, pRtsp);/* Bad Request */
            return ERR_NOERROR;
        }
    }

    cseq = pRtsp->rtsp_cseq;


    //发送option处理后的消息
    send_options_reply(pRtsp, cseq);

    return ERR_NOERROR;
}

int send_setup_reply(RTSP_buffer *pRtsp, RTSP_session *pSession, RTP_session *pRtpSes)
{
	char s8Str[1024];
	sprintf(s8Str, "%s %d %s"RTSP_EL"CSeq: %ld"RTSP_EL"Server: %s/%s"RTSP_EL, RTSP_VER,\
			200, get_stat(200), (long int)pRtsp->rtsp_cseq, PACKAGE, VERSION);
	add_time_stamp(s8Str, 0);
	sprintf(s8Str + strlen(s8Str), "Session: %d"RTSP_EL"Transport: ", (pSession->session_id));

    switch (pRtpSes->transport.type)
    {
		case RTP_rtp_avp:
			if (pRtpSes->transport.u.udp.is_multicast)
			{
//				sprintf(s8Str + strlen(s8Str), "RTP/AVP;multicast;ttl=%d;destination=%s;port=", (int)DEFAULT_TTL, descr->multicast);
			}
			else
			{
				sprintf(s8Str + strlen(s8Str), "RTP/AVP;unicast;client_port=%d-%d;server_port=", \
						pRtpSes->transport.u.udp.cli_ports.RTP, pRtpSes->transport.u.udp.cli_ports.RTCP);
			}

			sprintf(s8Str + strlen(s8Str), "%d-%d"RTSP_EL, pRtpSes->transport.u.udp.ser_ports.RTP, pRtpSes->transport.u.udp.ser_ports.RTCP);
			break;

		case RTP_rtp_avp_tcp:
			sprintf(s8Str + strlen(s8Str), "RTP/AVP/TCP;interleaved=%d-%d"RTSP_EL, \
					pRtpSes->transport.u.tcp.interleaved.RTP, pRtpSes->transport.u.tcp.interleaved.RTCP);
			break;

		default:
			break;
    }

    strcat(s8Str, RTSP_EL);
    bwrite(s8Str, (unsigned short) strlen(s8Str), pRtsp);

     return ERR_NOERROR;
}

int RTSP_get_local_port(int s)
{
	
	struct sockaddr addr;
	struct sockaddr_in* addr_v4;
	int addr_len = sizeof(addr);
	
	if (0 == getsockname(s, &addr, &addr_len))
	{
		if (addr.sa_family == AF_INET)
		{
			 addr_v4 = (struct sockaddr_in*)&addr;
			
			 return ntohs(addr_v4->sin_port);
		}
	}
	
	return -1;
}

int RTSP_setup(RTSP_buffer * pRtsp)
{
	char s8TranStr[128], *s8Str;
	char *pStr;
	RTP_transport Transport;
	int s32SessionID=0;
	RTP_session *rtp_s, *rtp_s_prec;
	RTSP_session *rtsp_s;
	struct sockaddr_storage rtsp_peer;
//	struct ifreq stIfr;
    socklen_t namelen = sizeof(rtsp_peer);
	EmRtpPayload		emPayload;
	int index;
	

	if ((s8Str = strstr(pRtsp->in_buffer, HDR_TRANSPORT)) == NULL)
	{
		fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
		send_reply(406, 0, pRtsp);     // Not Acceptable
		return ERR_NOERROR;
	}

	//检查传输层子串是否正确
	if (sscanf(s8Str, "%*10s %255s", s8TranStr) != 1)
	{
		fprintf(stderr,"SETUP request malformed: Transport string is empty\n");
		send_reply(400, 0, pRtsp);       // Bad Request
		return ERR_NOERROR;
	}

	if(getpeername(pRtsp->fd, (struct sockaddr *)&rtsp_peer, &namelen) != 0)
    {
        send_reply(415, 0, pRtsp);/*服务器内部错误*/
        return ERR_GENERIC;
    }

	emPayload=_unkonw;

	Transport.type = RTP_no_transport;

	if ((s8Str = strstr(pRtsp->in_buffer, "trackID=0")) != NULL)
	{
		emPayload=_h264;
	}
	else if ((s8Str = strstr(pRtsp->in_buffer, "trackID=1")) != NULL)
	{
		emPayload=_g711;
	}

	if (emPayload == _unkonw)
	{
		fprintf(stderr,"Unsupported Media,%s,%d\n", __FILE__, __LINE__);
		send_reply(415, 0, pRtsp);// Bad Request
		return ERR_NOERROR;
	}

	if(!RtspVerifyUrl(&index,pRtsp->in_buffer))
	{
		PRINT_DBG("RtspVerifyUrl Error!!!\n");
		send_reply(400, 0, pRtsp);  /* Bad Request */
		return ERR_NOERROR;
	}

	
	if((pStr = strstr(s8TranStr, RTSP_RTP_AVP)))
	{
		//Transport: RTP/AVP
		pStr += strlen(RTSP_RTP_AVP);
		//printf("s8TranStr=%s\n",s8TranStr);
		if ( !*pStr || (*pStr == ';') || (*pStr == ' '))
		{
			//单播
			if (strstr(s8TranStr, "unicast"))
			{
				//如果指定了客户端端口号，填充对应的两个端口号
				if( (pStr = strstr(s8TranStr, "client_port")) )
				{
					pStr = strstr(s8TranStr, "=");
					sscanf(pStr + 1, "%d", &(Transport.u.udp.cli_ports.RTP));
					pStr = strstr(s8TranStr, "-");
					sscanf(pStr + 1, "%d", &(Transport.u.udp.cli_ports.RTCP));
				}

#if 1
				//服务器端口
				if (RTP_get_port_pair(&Transport.u.udp.ser_ports) != ERR_NOERROR)
				{
					fprintf(stderr, "Error %s,%d\n", __FILE__, __LINE__);
					send_reply(500, 0, pRtsp);/* Internal server error */
					return ERR_GENERIC;
				}
#else
				//固定写死，但不起作用
				Transport.u.udp.ser_ports.RTP=10004;
				Transport.u.udp.ser_ports.RTCP=10005;

#endif

				//udp_connect(Transport.u.udp.cli_ports.RTP, &Transport.u.udp.rtp_peer, (*((struct sockaddr_in *) (&rtsp_peer))).sin_addr.s_addr, &Transport.rtp_fd);
				/*发出RTCP数据包的UDP连接*/
				//udp_connect(Transport.u.udp.cli_ports.RTCP, &Transport.u.udp.rtcp_out_peer, (*((struct sockaddr_in *) (&rtsp_peer))).sin_addr.s_addr, &Transport.rtcp_fd_out);
				//udp_open(Transport.u.udp.ser_ports.RTCP, &Transport.u.udp.rtcp_in_peer, &Transport.rtcp_fd_in); //bind

				struct sockaddr_in server;
				int len =sizeof(server);
				int socket1,localPort;
				struct sockaddr_in sin;   

				
				server.sin_family=AF_INET;
				server.sin_port=htons(Transport.u.udp.cli_ports.RTP);		   
				server.sin_addr.s_addr=(*((struct sockaddr_in *) (&rtsp_peer))).sin_addr.s_addr; 
				socket1=socket(AF_INET,SOCK_DGRAM,0);

				memset (&sin, 0, sizeof (sin));  
        		sin.sin_family = PF_INET;  
       			sin.sin_port = htons (Transport.u.udp.ser_ports.RTP); 

				if (bind(socket1, (struct sockaddr*) &sin, sizeof(struct sockaddr)) ==  - 1)
			    {
			        close(socket1);
			        return  ERR_GENERIC;
			    }
				
				if(connect(socket1, (struct sockaddr *)&server, len))
				{
					printf("rtp connect fail...............................\n");
					close(socket1);
					return ERR_GENERIC;
				}
				
#if 0

				localPort=RTSP_get_local_port(socket1);
				if(localPort<0)
				{
					close(socket1);
					return ERR_GENERIC;
				}

				printf(".............localPort=%d\n",localPort);
				
				Transport.u.udp.ser_ports.RTP=localPort;
				Transport.u.udp.ser_ports.RTCP=localPort+1;
					
#endif
				Transport.rtp_fd=socket1;

				Transport.rtcp_fd_out = -1;
				Transport.rtcp_fd_in = -1;
				Transport.u.udp.is_multicast = 0;
				//printf("port=%d ,Transport.rtp_fd=%d\n",Transport.u.udp.cli_ports.RTP,Transport.rtp_fd);

			}
			else
			{
				//multicast 多播处理....
			}
			
			Transport.type = RTP_rtp_avp;
		}
		else if (strstr(s8TranStr, "/TCP")!=NULL)
		{
			if( (pStr = strstr(s8TranStr, "interleaved")) )
			{
				pStr = strstr(s8TranStr, "=");
				sscanf(pStr + 1, "%d", &(Transport.u.tcp.interleaved.RTP));
				if ((pStr = strstr(pStr, "-")))
					sscanf(pStr + 1, "%d", &(Transport.u.tcp.interleaved.RTCP));
				else
					Transport.u.tcp.interleaved.RTCP = Transport.u.tcp.interleaved.RTP + 1;
			
				Transport.rtp_fd = pRtsp->fd;
				Transport.rtcp_fd_out = pRtsp->fd;
				Transport.rtcp_fd_in = -1;
				Transport.type = RTP_rtp_avp_tcp;
			}

		}
	}

	if (Transport.type == RTP_no_transport)
	{
		fprintf(stderr,"Unsupported Transport,%s,%d\n", __FILE__, __LINE__);
		send_reply(461, 0, pRtsp);// Bad Request
		return ERR_NOERROR;
	}


	//如果有会话头，就有了一个控制集合
	if ((pStr = strstr(pRtsp->in_buffer, HDR_SESSION)) != NULL)
	{
		if (sscanf(pStr, "%*s %d", &s32SessionID) != 1)
		{
			fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
			send_reply(454, 0, pRtsp); // Session Not Found
			return ERR_NOERROR;
		}
	}
	else
	{
		//产生一个非0的随机的会话序号
		struct timeval stNowTmp;
		gettimeofday(&stNowTmp, 0);
		srand((stNowTmp.tv_sec * 1000) + (stNowTmp.tv_usec / 1000));
		s32SessionID = 1 + (int) (10.0 * rand() / (100000 + 1.0));
		if (s32SessionID == 0)
		{
			s32SessionID++;
		}
	}
	

	//如果需要增加一个会话
	if ( !pRtsp->session_list )
	{
		printf("add a rtsp session\n");
		pRtsp->session_list = (RTSP_session *) calloc(1, sizeof(RTSP_session));
	}
	rtsp_s = pRtsp->session_list;

	//建立一个新会话，插入到链表中
	if (pRtsp->session_list->rtp_session == NULL)
	{
		printf("add a rtp session\n");
		pRtsp->session_list->rtp_session = (RTP_session *) calloc(1, sizeof(RTP_session));
		rtp_s = pRtsp->session_list->rtp_session;
		rtp_s->next=NULL;
	}
	else
	{
		for (rtp_s = rtsp_s->rtp_session; rtp_s != NULL; rtp_s = rtp_s->next)
		{
			rtp_s_prec = rtp_s;
		}
		printf("add another rtp session\n");
		rtp_s_prec->next = (RTP_session *) calloc(1, sizeof(RTP_session));
		rtp_s = rtp_s_prec->next;
		rtp_s->next=NULL;
	}


	
	memcpy(&rtp_s->transport, &Transport, sizeof(Transport));
#if 0
	strcpy(stIfr.ifr_name, "eth0");
    ioctl(rtp_s->transport.rtp_fd, SIOCGIFADDR, &stIfr);
#endif
	
//	rtp_s->u32SSrc =htonl(inet_addr(g_stHLAllParam.stNetParam.szLocalIpAddr));
		//起始状态为暂停
	rtp_s->emPayload=emPayload;
	rtp_s->byFirstTime=1;
	rtp_s->videoIndex=index;
	rtp_s->u32TimeStamp=0;
	rtp_s->pause = 1;
	rtp_s->started=0;
	rtp_s->nSeq=0;
	pRtsp->session_list->session_id = s32SessionID;
	rtp_s->sched_id = schedule_add(rtp_s);
	rtp_s->pRtsp=(void *)pRtsp;//为了在rtp出错时关掉rtsp
	send_setup_reply(pRtsp, rtsp_s, rtp_s);

	return ERR_NOERROR;
}

int send_play_reply(RTSP_buffer * pRtsp, RTSP_session * pRtspSesl)
{
	char s8Str[1024];
	char s8Temp[30];
	sprintf(s8Str, "%s %d %s"RTSP_EL"CSeq: %d"RTSP_EL"Server: %s/%s"RTSP_EL, RTSP_VER, 200,\
			get_stat(200), pRtsp->rtsp_cseq, PACKAGE, VERSION);
	add_time_stamp(s8Str, 0);

	sprintf(s8Temp, "Session: %d"RTSP_EL, pRtspSesl->session_id);
	strcat(s8Str, s8Temp);
	strcat(s8Str, RTSP_EL);

	bwrite(s8Str, (unsigned short) strlen(s8Str), pRtsp);

	return ERR_NOERROR;
}

int RTSP_play(RTSP_buffer * pRtsp)
{
	char *pStr;
	char pTrash[128];
	long int s32SessionId;
	RTSP_session *pRtspSel;
	RTP_session *pRtpSel;

	//获取CSeq
	if ((pStr = strstr(pRtsp->in_buffer, HDR_CSEQ)) == NULL)
	{
		fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
		send_reply(400, 0, pRtsp);   /* Bad Request */
		return ERR_NOERROR;
	}
	else
	{
		if (sscanf(pStr, "%254s %d", pTrash, &(pRtsp->rtsp_cseq)) != 2)
		{
			fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
			send_reply(400, 0, pRtsp);    /* Bad Request */
			return ERR_NOERROR;
		}
	}

	//获取session
	if ((pStr = strstr(pRtsp->in_buffer, HDR_SESSION)) != NULL)
	{
		if (sscanf(pStr, "%254s %ld", pTrash, &s32SessionId) != 2)
		{
			send_reply(454, 0, pRtsp);// Session Not Found
			return ERR_NOERROR;
		}
	}
	else
	{
		fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
		send_reply(400, 0, pRtsp);// bad request
		return ERR_NOERROR;
	}

	//时间参数,假设都是 0-0,不做设置
/*	if ((pStr = strstr(pRtsp->in_buffer, HDR_RANGE)) != NULL)
	{
		if((pStrTime = strstr(pRtsp->in_buffer, "npt")) != NULL)
		{
			if((pStrTime = strstr(pStrTime, "=")) == NULL)
			{
				send_reply(400, 0, pRtsp);// Bad Request
				return ERR_NOERROR;
			}

		}
		else
		{

		}
	}
*/
	//播放list指向的rtp session
	pRtspSel = pRtsp->session_list;
	int nyCount=0;
	if (pRtspSel != NULL)
	{
		if (pRtspSel->session_id == s32SessionId)
		{
			//查找RTP session,播放list中所有的session，本例程只有一个成员.
			for (pRtpSel = pRtspSel->rtp_session; pRtpSel != NULL; pRtpSel = pRtpSel->next)
			{
				//播放所有演示
				nyCount++;
				//printf("Session Count=%d pRtpSel->sched_id=%d pRtpSel->started=%d emPayload=%d-------------------\n",nyCount,pRtpSel->sched_id,pRtpSel->started,pRtpSel->emPayload);
				if (!pRtpSel->started)
				{
					//开始新的播放
					printf("\t+++++++++++++++++++++\n");
					printf("\tstart to play %d now!\n", pRtpSel->sched_id);
					printf("\t+++++++++++++++++++++\n");

					if (schedule_start(pRtpSel->sched_id, NULL) == ERR_ALLOC)
					{
						return ERR_ALLOC;
					}
				}
				else
				{
					//恢复暂停，播放
					if (!pRtpSel->pause)
					{
						//fnc_log(FNC_LOG_INFO,"PLAY: already playing\n");
					}
					else
					{
//						schedule_resume(pRtpSel->sched_id, NULL);
					}
				}

			}
		}
		else
		{
			send_reply(454, 0, pRtsp);	// Session not found
			return ERR_NOERROR;
		}
	}
	else
	{
		send_reply(415, 0, pRtsp);  // Internal server error
		return ERR_GENERIC;
	}

	send_play_reply(pRtsp, pRtspSel);

	return ERR_NOERROR;
}

int send_teardown_reply(RTSP_buffer * pRtsp, long SessionId, long cseq)
{
    char s8Str[1024];
    char s8Temp[30];

    // 构建回复消息
    sprintf(s8Str, "%s %d %s"RTSP_EL"CSeq: %ld"RTSP_EL"Server: %s/%s"RTSP_EL, RTSP_VER,\
    		200, get_stat(200), cseq, PACKAGE, VERSION);
    //添加时间戳
    add_time_stamp(s8Str, 0);
    //会话ID
    sprintf(s8Temp, "Session: %ld"RTSP_EL, SessionId);
    strcat(s8Str, s8Temp);

    strcat(s8Str, RTSP_EL);

    //写入缓冲区
    bwrite(s8Str, (unsigned short) strlen(s8Str), pRtsp);

    return ERR_NOERROR;
}


int RTSP_teardown(RTSP_buffer * pRtsp)
{
	char *pStr;
	char pTrash[128];
	long int s32SessionId;
	RTSP_session *pRtspSel;
	RTP_session *pRtpSel;

	//获取CSeq
	if ((pStr = strstr(pRtsp->in_buffer, HDR_CSEQ)) == NULL)
	{
		fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
		send_reply(400, 0, pRtsp);   // Bad Request
		return ERR_NOERROR;
	}
	else
	{
		if (sscanf(pStr, "%254s %d", pTrash, &(pRtsp->rtsp_cseq)) != 2)
		{
			fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
			send_reply(400, 0, pRtsp);    // Bad Request
			return ERR_NOERROR;
		}
	}

	//获取session
	if ((pStr = strstr(pRtsp->in_buffer, HDR_SESSION)) != NULL)
	{
		if (sscanf(pStr, "%254s %ld", pTrash, &s32SessionId) != 2)
		{
			send_reply(454, 0, pRtsp);	// Session Not Found
			return ERR_NOERROR;
		}
	}
	else
	{
		s32SessionId = -1;
	}

	pRtspSel = pRtsp->session_list;
	if (pRtspSel == NULL)
	{
		send_reply(415, 0, pRtsp);  // Internal server error
		return ERR_GENERIC;
	}

	if (pRtspSel->session_id != s32SessionId)
	{
		send_reply(454, 0, pRtsp);	// Session not found
		return ERR_NOERROR;
	}

	//向客户端发送响应消息
	send_teardown_reply(pRtsp, s32SessionId, pRtsp->rtsp_cseq);

	//释放所有的URI RTP会话
	RTP_session *pRtpSelTemp;
	pRtpSel = pRtspSel->rtp_session;
	while (pRtpSel != NULL)
	{
		pRtpSelTemp = pRtpSel;

		pRtspSel->rtp_session = pRtpSel->next;

		pRtpSel = pRtpSel->next;
		//删除schedule中对应id
		schedule_remove(pRtpSelTemp->sched_id);
		//全局变量播放总数减一，如果为0则不播放

	}

	//释放链表空间
	if (pRtspSel->rtp_session == NULL)
	{
		free(pRtsp->session_list);
		printf("free(pRtsp->session_list) 1692;..................\n");
		pRtsp->session_list = NULL;
	}

	return ERR_NOERROR;
}

/*rtsp状态机，服务器端*/
void RTSP_state_machine(RTSP_buffer * pRtspBuf, int method)
{


    /*除了播放过程中发送的最后一个数据流，
     *所有的状态迁移都在这里被处理
     * 状态迁移位于stream_event中
     */
    char *s;
    RTSP_session *pRtspSess;
    long int session_id;
    char trash[255];
  //  char szDebug[255];

    /*找到会话位置*/
    if ((s = strstr(pRtspBuf->in_buffer, HDR_SESSION)) != NULL)
    {
        if (sscanf(s, "%254s %ld", trash, &session_id) != 2)
        {
            fprintf(stderr,"Invalid Session number %s,%i\n", __FILE__, __LINE__);
            send_reply(454, 0, pRtspBuf);              /* 没有此会话*/
            return;
        }
    }

    /*打开会话列表*/
    pRtspSess = pRtspBuf->session_list;
    if (pRtspSess == NULL)
    {
        return;
    }

    /*根据状态迁移规则，从当前状态开始迁移*/
    switch (pRtspSess->cur_state)
    {
        case INIT_STATE:                    /*初始态*/
        {
#ifdef RTSP_DEBUG
        	fprintf(stderr,"current method code is:  %d  \n",method);
#endif
            switch (method)
            {
                case RTSP_ID_DESCRIBE:  //状态不变
                    RTSP_describe(pRtspBuf);
                    break;

                case RTSP_ID_SETUP:                //状态变为就绪态
                  if (RTSP_setup(pRtspBuf) == ERR_NOERROR)
                    {
                    	pRtspSess->cur_state = READY_STATE;
                        fprintf(stderr,"TRANSFER TO READY STATE!\n");
                    }
                    break;

                case RTSP_ID_TEARDOWN:       //状态不变
                    RTSP_teardown(pRtspBuf);
                    break;

                case RTSP_ID_OPTIONS:
                    if (RTSP_options(pRtspBuf) == ERR_NOERROR)
                    {
                    	pRtspSess->cur_state = INIT_STATE;         //状态不变
                    }
                    break;

                case RTSP_ID_PLAY:          //method not valid this state.

                case RTSP_ID_PAUSE:
                    send_reply(455, 0, pRtspBuf);
                    break;

                default:
                    send_reply(501, 0, pRtspBuf);
                    break;
            }
        break;
        }

        case READY_STATE:
        {


            switch (method)
            {
                case RTSP_ID_PLAY:                                      //状态迁移为播放态
                   if (RTSP_play(pRtspBuf) == ERR_NOERROR)
                    {
                       // fprintf(stderr,"\tStart Playing!\n");
                        pRtspSess->cur_state = PLAY_STATE;
                    }
                    break;

                case RTSP_ID_SETUP:
                    if (RTSP_setup(pRtspBuf) == ERR_NOERROR)    //状态不变
                    {
                        pRtspSess->cur_state = READY_STATE;
                    }
                    break;

                case RTSP_ID_TEARDOWN:
                    RTSP_teardown(pRtspBuf);                 //状态变为初始态 ?
                    break;

                case RTSP_ID_OPTIONS:
                    if (RTSP_options(pRtspBuf) == ERR_NOERROR)
                    {
                        pRtspSess->cur_state = INIT_STATE;          //状态不变
                    }
                    break;

                case RTSP_ID_PAUSE:         			// method not valid this state.
                    send_reply(455, 0, pRtspBuf);
                    break;

                case RTSP_ID_DESCRIBE:
                    RTSP_describe(pRtspBuf);
                    break;

                default:
                    send_reply(501, 0, pRtspBuf);
                    break;
            }

            break;
        }


        case PLAY_STATE:
        {
            switch (method)
            {
                case RTSP_ID_PLAY:
                    // Feature not supported
                    fprintf(stderr,"UNSUPPORTED: Play while playing.\n");
                    send_reply(551, 0, pRtspBuf);        // Option not supported
                    break;

                case RTSP_ID_PAUSE:              	//状态变为就绪态
#if 0
                    if (RTSP_pause(pRtspBuf) == ERR_NOERROR)
                    {
                    	pRtspSess->cur_state = READY_STATE;
                    }
#endif
					fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
					send_reply(400, 0, pRtspBuf);
                    break;

                case RTSP_ID_TEARDOWN:
                    RTSP_teardown(pRtspBuf);        //状态迁移为初始态
                    break;

                case RTSP_ID_OPTIONS:
					RTSP_options(pRtspBuf);
                    break;

                case RTSP_ID_DESCRIBE:
                    RTSP_describe(pRtspBuf);
                    break;

                case RTSP_ID_SETUP:
                    break;
            }

            break;
        }/* PLAY state */

        default:
            {
                /* invalid/unexpected current state. */
                fprintf(stderr,"%s State error: unknown state=%d, method code=%d\n", __FUNCTION__, pRtspSess->cur_state, method);
            }
            break;
    }/* end of current state switch */

}

void RTSP_remove_msg(int len, RTSP_buffer * rtsp)
{
    rtsp->in_size -= len;
    if (rtsp->in_size && len)
    {
        //删除指定长度的消息
        memmove(rtsp->in_buffer, &(rtsp->in_buffer[len]), RTSP_BUFFERSIZE - len);
        memset(&(rtsp->in_buffer[RTSP_BUFFERSIZE - len]), 0, len);
    }
	//printf("remove message rtsp->in_size=%d\n",rtsp->in_size);
}

void RTSP_discard_msg(RTSP_buffer * rtsp)
{
    int hlen, blen;

    //找出缓冲区中首个消息的长度，然后删除
    if (RTSP_full_msg_rcvd(rtsp, &hlen, &blen) > 0)
        RTSP_remove_msg(hlen + blen, rtsp);
}



int RTSP_handler(RTSP_buffer *rtsp)
{
    /*DEBUG_PRINTF("entering rtsp_handler!\n");*/

    /*定义变量*/
    unsigned short status;
    //char msg[100];
    int m, op;
    int full_msg;
    RTP_session *rtp_s;
    int hlen, blen;

    while (rtsp->in_size)
    {
        /*根据收到的消息类型进行各自的处理*/
        switch ( (full_msg = RTSP_full_msg_rcvd(rtsp, &hlen, &blen)) )
        {
        case RTSP_method_rcvd:
            op = RTSP_valid_response_msg(&status, rtsp);     /*检查缓冲区的响应消息是否正确*/

            if (op == 0)                          /*不是一个响应消息，所以是客户端的请求*/
            {
                /*不存在输出消息，因此 它是客户端发送的一个请求*/
                m = RTSP_validate_method(rtsp);
                if (m < 0)
                {
                    /*错误的请求，请求的方法不存在*/
                  //  fnc_log(FNC_LOG_INFO, "Bad Request ");
                  fprintf(stderr, "Error %s,%i\n", __FILE__, __LINE__);
                    send_reply(400, NULL, rtsp);
                }
                else
                {
                    RTSP_state_machine(rtsp, m);           /*进入到状态机*/
                }
            }
            else
            {
                if (op == ERR_GENERIC)                       /*序列号错误*/
                {
                }
                else
                {
                }
            }
            RTSP_discard_msg(rtsp);                 /*丢弃消息*/
            break;

        case RTSP_interlvd_rcvd:
            m = rtsp->in_buffer[1];                       /*通道标志符的ASCII码*/

            /*处理会话列表中的每一个会话*/
            for (rtp_s = (rtsp->session_list) ? (rtsp->session_list->rtp_session) : NULL; \
                    rtp_s && ((rtp_s->transport.u.tcp.interleaved.RTP == m) || (rtp_s->transport.u.tcp.interleaved.RTCP == m)); \
                    rtp_s = rtp_s->next)
            {
                if (rtp_s)
                {
                    /*到达的是RTCP包*/
                    if (m == rtp_s->transport.u.tcp.interleaved.RTCP)
                    {
                      //  printf( "Interleaved RTCP packet arrived for channel %d (len: %d).\n", m, blen);

                        /*将数据拷贝到RTCP_inbuffer中*/
                        if (sizeof(rtp_s->rtcp_inbuffer) >= hlen + blen)
                        {
                            memcpy(rtp_s->rtcp_inbuffer, &rtsp->in_buffer[hlen], hlen + blen);
                            rtp_s->rtcp_insize = blen;
                        }
                        else
                        {
                            //fnc_log(FNC_LOG_DEBUG, "Interleaved RTCP packet too big!.\n", m);
						}
                        //RTCP_recv_packet(rtp_s);
                    }
                    else
                    {
                        /*rtp 不做任何处理*/
                       // fnc_log(FNC_LOG_DEBUG, "Interleaved RTP packet arrived for channel %d.\n", m);
                    }
                }
                else
                	{
                    //fnc_log(FNC_LOG_DEBUG, "Interleaved RTP or RTCP packet arrived for unknown channel (%d)... discarding.\n", m);
					}
            }

            RTSP_discard_msg(rtsp);
            break;

        default:
			//printf("full_msg=%d\n",full_msg);
			RTSP_remove_msg(rtsp->in_size,rtsp);
            return full_msg;
            break;
        }
    }

   /// DEBUG_PRINT_INFO("leaving rtsp_handler!");                  /*just for debug,yanf*/

    return ERR_NOERROR;
}


int RtspServer(RTSP_buffer *rtsp)
{
	fd_set rset,wset;       /*读写I/O描述集*/
	struct timeval t;
	int size;
	static char buffer[RTSP_BUFFERSIZE+1]; /* +1 to control the final '\0'*/
	int n;
	int res,iRet=0;
	struct sockaddr ClientAddr;

	if (rtsp == NULL)
	{
		return ERR_NOERROR;
	}

	if(rtsp->iNeedClose==1)
	{
		return ERR_GENERIC;
	}

	/*变量初始化*/
	FD_ZERO(&rset);
	FD_ZERO(&wset);
	t.tv_sec=0;				/*select 时间间隔*/
	t.tv_usec=100000;

	FD_SET(rtsp->fd,&rset);

	/*调用select等待对应描述符变化*/
	iRet=select(rtsp->fd+1,&rset,0,0,&t);
	if (iRet<0)
	{
		PRINT_DBG("select error \n");
		send_reply(500, NULL, rtsp);
		return ERR_GENERIC; //errore interno al server
	}


	/*有可供读进的rtsp包*/
	if (FD_ISSET(rtsp->fd,&rset))
	{
		memset(buffer,0,sizeof(buffer));
		size=sizeof(buffer)-1;  /*最后一位用于填充字符串结束标识*/

		/*读入数据到缓冲区中*/

		n= tcp_read(rtsp->fd, buffer, size, &ClientAddr);
		if (n==0)
		{
			return ERR_CONNECTION_CLOSE;
		}

		if (n<0)
		{
			PRINT_DBG("read() error \n");
			send_reply(500, NULL, rtsp);                //服务器内部错误消息
			return ERR_GENERIC;
		}

		//检查读入的数据是否产生溢出
		if (rtsp->in_size+n>RTSP_BUFFERSIZE)
		{
			PRINT_DBG("RTSP buffer overflow (rtsp->in_size=%d).\n",rtsp->in_size);
			send_reply(500, NULL, rtsp);
			return ERR_GENERIC;//数据溢出错误
		}


		//printf("INPUT_BUFFER was:\n<<<<<<<<\n%s\n", buffer);


		/*填充数据*/
		memcpy(&(rtsp->in_buffer[rtsp->in_size]),buffer,n);
		rtsp->in_size+=n;
		//清空buffer
		memset(buffer, 0, n);
		//添加客户端地址信息
		memcpy(	&rtsp->stClientAddr, &ClientAddr, sizeof(ClientAddr));

		/*处理缓冲区的数据，进行rtsp处理*/
		if ((res=RTSP_handler(rtsp))==ERR_GENERIC)
		{
			//fprintf(stderr,"Invalid input message.\n");
			return ERR_NOERROR;
		}
	}

	/*有发送数据*/
	if (rtsp->out_size>0)
	{
		//将数据发送出去
		n= tcp_write(rtsp->fd,rtsp->out_buffer,rtsp->out_size);
		if (n<0)
		{
			PRINT_DBG("tcp_write error \n");
			send_reply(500, NULL, rtsp);
			return ERR_GENERIC; //errore interno al server
		}


		//printf("OUTPUT_BUFFER length %d\n\n>>>>>>>>\n%s\n", rtsp->out_size, rtsp->out_buffer);

		//清空发送缓冲区
		memset(rtsp->out_buffer, 0, rtsp->out_size);
		rtsp->out_size = 0;
	}


	//如果需要RTCP在此出加入对RTCP数据的接收，并存放在缓存中。
	//继而在schedule_do线程中对其处理。
	//rtcp控制处理,检查读入RTCP数据报


	return ERR_NOERROR;
}

int RTCP_recv_packet(RTP_session *session)
{
    short len=0;
    for (len=0; len<session->rtcp_insize; len+=(ntohs(*((short*)&(session->rtcp_inbuffer[len+2])))+1)*4) 
    {
        /*解析数据包的类型,做不同的内部处理*/
        switch (session->rtcp_inbuffer[1+len]) 
        {
            case SR: 
                {
                    int ssrc_count,i;
                    unsigned char tmp[4];
                    printf("RTCP SR packet received\n");

                    /*填充缓冲区中的各个变量*/
                    session->rtcp_stats[i_client].SR_received += 1;
                    session->rtcp_stats[i_client].pkt_count=*((int*)&(session->rtcp_inbuffer[20+len]));
                    session->rtcp_stats[i_client].octet_count=*((int*)&(session->rtcp_inbuffer[24+len]));
                    ssrc_count=session->rtcp_inbuffer[0+len] & 0x1f;
                    
                    for (i=0; i<ssrc_count; ++i) 
                    {
                        session->rtcp_stats[i_client].fract_lost=session->rtcp_inbuffer[32+len];
                        tmp[0]=0;
                        tmp[1]=session->rtcp_inbuffer[33+len];
                        tmp[2]=session->rtcp_inbuffer[34+len];
                        tmp[3]=session->rtcp_inbuffer[35+len];
                        session->rtcp_stats[i_client].pkt_lost=ntohl(*((int*)tmp));
                        session->rtcp_stats[i_client].highest_seq_no=ntohl(session->rtcp_inbuffer[36+len]);
                        session->rtcp_stats[i_client].jitter=ntohl(session->rtcp_inbuffer[40+len]);
                        session->rtcp_stats[i_client].last_SR=ntohl(session->rtcp_inbuffer[44+len]);
                        session->rtcp_stats[i_client].delay_since_last_SR=ntohl(session->rtcp_inbuffer[48+len]);
                    }
                    break;
                }
                
            case RR: 
                {
                    int ssrc_count,i;
                    unsigned char tmp[4];
                    printf("RTCP RR packet received\n");
                    session->rtcp_stats[i_client].RR_received += 1;
                    ssrc_count=session->rtcp_inbuffer[0+len] & 0x1f;
                    for (i=0; i<ssrc_count; ++i) {
                    session->rtcp_stats[i_client].fract_lost=session->rtcp_inbuffer[12+len];
                    tmp[0]=0;
                    tmp[1]=session->rtcp_inbuffer[13+len];
                    tmp[2]=session->rtcp_inbuffer[14+len];
                    tmp[3]=session->rtcp_inbuffer[15+len];
                    session->rtcp_stats[i_client].pkt_lost=ntohl(*((int*)tmp));
                    session->rtcp_stats[i_client].highest_seq_no=ntohl(session->rtcp_inbuffer[16+len]);
                    session->rtcp_stats[i_client].jitter=ntohl(session->rtcp_inbuffer[20+len]);
                    session->rtcp_stats[i_client].last_SR=ntohl(session->rtcp_inbuffer[24+len]);
                    session->rtcp_stats[i_client].delay_since_last_SR=ntohl(session->rtcp_inbuffer[28+len]);
                    }   
                    break;
                }
                
            case SDES: 
                {
                    printf("RTCP SDES packet received\n");
                    switch (session->rtcp_inbuffer[8]) 
                    {
                        case CNAME: 
                            {
                                session->rtcp_stats[1].dest_SSRC=ntohs(*((int*)&(session->rtcp_inbuffer[4])));
                                break;
                            }
                            
                        case NAME:
                            {
                                break;
                            }
                            
                        case EMAIL: 
                            {
                                break;
                            }
                            
                        case PHONE: 
                            {
                                break;
                            }
                            
                        case LOC:
                            {
                                break;
                            }
                        case TOOL: 
                            {
                                break;
                            }
                            
                        case NOTE:
                            {
                                break;
                            }
                            
                        case PRIV: 
                            {
                                break;
                            }
                            
                    }
                    
                    break;
                }
                
            case BYE:
                {   
                    printf("RTCP BYE packet received\n");
                    break;
                }
                
            case APP:
                {
                    printf("RTCP APP packet received\n");
                    break;
                }
                
            default: 
                {
                    printf("Unknown RTCP received and ignored.\n");
                    return ERR_NOERROR;
                }
                
        }
        
    }
    
    return ERR_NOERROR;
}


void ScheduleConnections(RTSP_buffer **rtsp_list, int *conn_count)
{
    int res;
    RTSP_buffer *pRtsp=*rtsp_list,*pRtspN=NULL;
    RTP_session *r=NULL, *t=NULL;

    while (pRtsp!=NULL)
    {
        if ((res = RtspServer(pRtsp))!=ERR_NOERROR)
        {
            if (res==ERR_CONNECTION_CLOSE || res==ERR_GENERIC)
            {
                /*连接已经关闭*/
                if (res==ERR_CONNECTION_CLOSE)
                {
					fprintf(stderr,"RTSP connection closed by client.\n");
				} 
                else
                {
                	fprintf(stderr,"RTSP connection closed by server.\n");
                }

                /*客户端在发送TEARDOWN 之前就截断了连接，但是会话却没有被释放*/
                if (pRtsp->session_list!=NULL)
                {
                    r=pRtsp->session_list->rtp_session;
                    /*释放所有会话*/
                    while (r!=NULL)
                    {
                        t = r->next;
                        schedule_remove(r->sched_id);
                        r=t;
                    }

                    /*释放链表头指针*/
                    free(pRtsp->session_list);
                    pRtsp->session_list=NULL;

                    fprintf(stderr,"WARNING! RTSP connection truncated before ending operations.\n");
                }

                // wait for
                close(pRtsp->fd);
				
                --*conn_count;
				
                /*释放rtsp缓冲区*/
                if (pRtsp==*rtsp_list)
                {
                	//链表第一个元素就出错，则pRtspN为空
                    *rtsp_list=pRtsp->next;
                    free(pRtsp);
                    pRtsp=*rtsp_list;
                }
                else
                {
                	//不是链表中的第一个，则把当前出错任务删除，并把next任务存放在pRtspN(上一个没有出错的任务)
                	//指向的next，和当前需要处理的pRtsp中.
                	pRtspN->next=pRtsp->next;
                    free(pRtsp);
                    pRtsp=pRtspN->next;
                }

                /*适当情况下，释放调度器本身*/
                if (pRtsp==NULL && *conn_count<0)
                {
                	fprintf(stderr,"to stop cchedule_do thread\n");
				//	HL_Reboot(-1);
					//reboot now
                }
            }
            else
            {
            	pRtsp = pRtsp->next;
            }
        }
        else
        {
        	//没有出错
        	//上一个处理没有出错的list存放在pRtspN中,需要处理的任务放在pRtst中
        	pRtspN = pRtsp;//没有出错，是上一个节点
            pRtsp = pRtsp->next;
        }
    }
}




