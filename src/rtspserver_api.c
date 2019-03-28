#include "rtp.h"
#include "rtsp.h"
#include "schedule.h"
#include "log.h"
#include "rtspserver_api.h"

VIDEOATTR stVideoAttr;

typedef struct _stHL_RTSP_Thread_S
{
	unsigned char    	byStop;
	int 			 	fd;
	int              	iCount;
	int 			 	iMaxNum;
	unsigned short   	nPort;
	SCHED_Thread_S	 	ScheduleThread;
	pthread_t		 	RtspThreadID;

} HL_RTSP_Thread, *PHL_RTSP_Thread;

static HL_RTSP_Thread   g_stHLRtspThread;


static int Base64Encode(char * pData, int dataSize, char* base64)
{
		const char base_64[128] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

		int	padding;
		int	i = 0, j = 0;
		
		char *	in;
		int	outSize;
		char *	out;

		unsigned int iOut = ((dataSize + 2) / 3) * 4;
		outSize = iOut += 2 * ((iOut / 60) + 1);
		out = base64;

		in = pData;

		if (outSize < (dataSize * 4 / 3)) return 0;

		while (i < dataSize) 	{
			padding = 3 - (dataSize - i);
			if (padding == 2) {
				out[j] = base_64[in[i]>>2];
				out[j+1] = base_64[(in[i] & 0x03) << 4];
				out[j+2] = '=';
				out[j+3] = '=';
			} else if (padding == 1) {
				out[j] = base_64[in[i]>>2];
				out[j+1] = base_64[((in[i] & 0x03) << 4) | ((in[i+1] & 0xf0) >> 4)];
				out[j+2] = base_64[(in[i+1] & 0x0f) << 2];
				out[j+3] = '=';
			} else{
				out[j] = base_64[in[i]>>2];
				out[j+1] = base_64[((in[i] & 0x03) << 4) | ((in[i+1] & 0xf0) >> 4)];
				out[j+2] = base_64[((in[i+1] & 0x0f) << 2) | ((in[i+2] & 0xc0) >> 6)];
				out[j+3] = base_64[in[i+2] & 0x3f];
			}
			i += 3;
			j += 4;
		}
		out[j] = '\0';
		return j;
}


int GetVideoAttr(char *buf)
{
		if(!buf)
		{
			return -1;
		}

		char szBase64sps_pps[128];
		char szProfileId[8];
		int iBase64Len=0,i;
		
		if(stVideoAttr.nSpsLen==0||stVideoAttr.nPpsLen==0)
		{
			return -1;
		}
		
		iBase64Len=Base64Encode(stVideoAttr.szSpsBuf,stVideoAttr.nSpsLen,szBase64sps_pps);
		
		szBase64sps_pps[iBase64Len]=',';
		iBase64Len++;
		iBase64Len+=Base64Encode(stVideoAttr.szPpsBuf,stVideoAttr.nPpsLen,szBase64sps_pps+iBase64Len);
		szBase64sps_pps[iBase64Len]='\0';
		for(i=0;i<3;i++)
		{
			sprintf(szProfileId+i*2,"%02X",stVideoAttr.szSpsBuf[1+i]);
		}
		
		szProfileId[6]='\0';
		sprintf(buf,"profile-level-id=%s; sprop-parameter-sets=%s; packetization-mode=1",szProfileId,szBase64sps_pps);
		PRINT_DBG("buf=%s\n",buf);
		return 0;
}

void EventLoop(PHL_RTSP_Thread pstThread)
{

	int s32Fd = -1;
	static RTSP_buffer *pRtspList=NULL;
	RTSP_buffer *p=NULL;
	unsigned int u32FdFound;

	s32Fd= tcp_accept(pstThread->fd);

	/*处理新创建的连接*/
	if (s32Fd >= 0)
	{
		/*查找列表中是否存在此连接的socket*/
		for (u32FdFound=0,p=pRtspList; p!=NULL; p=p->next)
		{
			if (p->fd == s32Fd)
			{
				u32FdFound=1;
				PRINT_DBG("FOUND Exist...............!\n");
				break;
			}
		}
		if (!u32FdFound)
		{
			/*创建一个连接，增加一个客户端*/
			if (pstThread->iCount<pstThread->iMaxNum)
			{
				pstThread->iCount++;
				AddClient(&pRtspList,s32Fd);
			}
			else
			{
				//fprintf(stderr, "exceed the MAX client, ignore this connecting\n");
				tcp_close(s32Fd);
				return;
			}
			PRINT_DBG(" Connection reached: %d\n", pstThread->iCount);
		}
	}

	ScheduleConnections(&pRtspList,&pstThread->iCount);
}

int RtspServerInit(int port)
{
	memset(&g_stHLRtspThread, 0, sizeof(g_stHLRtspThread));

	PHL_RTSP_Thread pstThread = &g_stHLRtspThread;

	pstThread->iMaxNum=4;
    pstThread->nPort = port;

	pstThread->byStop=1;
	pstThread->iCount=0;
	pstThread->RtspThreadID=-1;
	pstThread->fd=-1;
	pstThread->ScheduleThread.iMaxSched=pstThread->iMaxNum*2;//每个rtsp对应两个rtp，视频和音频
	pstThread->ScheduleThread.ScheduleThreadID=-1;

	frame_queue_init(&pstThread->ScheduleThread.bufQueue);
	frame_queue_start(&pstThread->ScheduleThread.bufQueue);
		
	if (ScheduleInit(&pstThread->ScheduleThread))
	{
		PRINT_DBG("Fatal: Can't start scheduler\nServer is aborting.\n");
		return -1;
	}
	
	//RTP_port_pool_init(RTP_DEFAULT_PORT,pstThread->iMaxNum);
	return 0;
	
}

int RtspServerDestroy()
{
	PHL_RTSP_Thread pstThread = &g_stHLRtspThread;
	ScheduleDestroy(&pstThread->ScheduleThread);
	pstThread->iCount=0;
	pstThread->RtspThreadID=-1;
	pstThread->fd=-1;
	return 0;
}

void *RtspEntrance(void *p)
{
	struct timespec ts = { 0, 1000000 };
	
	PHL_RTSP_Thread pstThread=(PHL_RTSP_Thread)p;
	
	while (!pstThread->byStop)
	{
		msleep(1);
		EventLoop(pstThread);
	}
	
	return NULL;
}


int RtspServerStart()
{
	int iRet=0;
	PHL_RTSP_Thread pstThread = &g_stHLRtspThread;	
	iRet= tcp_listen(pstThread->nPort);
	PRINT_DBG("iRet = %d, nPort = %d\n", iRet, pstThread->nPort);	
	if(iRet<0)
	{
		return -1;
	}
	pstThread->fd=iRet;

	pstThread->ScheduleThread.byStop=0;
	iRet=pthread_create(&pstThread->ScheduleThread.ScheduleThreadID,NULL,schedule_do,(void *)&pstThread->ScheduleThread);
	if(iRet)
	{
		return -1;
	}
	
	pstThread->byStop=0;
	iRet=pthread_create(&pstThread->RtspThreadID,NULL,RtspEntrance,(void *)pstThread);
	if(iRet)
	{
		return -1;
	}

	char sps[] = {0x67, 0x42, 0x80, 0x1f, 0xe4, 0x40, 0x5a, 0x05, 0x0d, 0x00, 0xda, 0x14, 0x26, 0xa0};
	char pps[] = {0x68, 0xce, 0x38, 0x80};
	stVideoAttr.nSpsLen = 14;
	stVideoAttr.nPpsLen = 4;

	memcpy(stVideoAttr.szSpsBuf, sps, 14);
	memcpy(stVideoAttr.szPpsBuf, pps, 4);
	return 0;
}

int RtspServerStop()
{
	PHL_RTSP_Thread pstThread = &g_stHLRtspThread;
	if(pstThread->RtspThreadID!=-1)
	{
		PRINT_DBG("\n");
		pthread_join(pstThread->RtspThreadID,NULL);
		PRINT_DBG("\n");		

	}
	
	if(pstThread->ScheduleThread.ScheduleThreadID!=-1)
	{	
		pthread_join(pstThread->ScheduleThread.ScheduleThreadID,NULL);
	}
	pstThread->byStop=1;
	pstThread->ScheduleThread.byStop=1;
	if(pstThread->fd!=-1)
	{
	//	tcp_close(pstThread->fd);
	}
	return 0;
}

int RtspSeverCount()
{
	return schedule_GetCount();
}

int RtspServerInputData(unsigned char * data, int length)
{
	if(NULL==data)
		return -1;

	if(data[4] == 0x67)
	{
		stVideoAttr.nSpsLen = 13;
		memcpy(stVideoAttr.szSpsBuf, data+4, 13);

		stVideoAttr.nPpsLen = 4;
		memcpy(stVideoAttr.szPpsBuf, data+4+13+4, 4);
	}
/*
	if(nal_unit_type == 0x07)
	{
		stVideoAttr.nSpsLen = length;
		memcpy(stVideoAttr.szSpsBuf, data, length);
	}
	else if(nal_unit_type == 0x08)
	{
		stVideoAttr.nPpsLen = length;
		memcpy(stVideoAttr.szPpsBuf, data, length);	
	}
*/		
	PHL_RTSP_Thread pstThread = &g_stHLRtspThread;	
	//if(schedule_GetCount() > 0)
	{
		pstThread->ScheduleThread.struNalu.pNalu=data;
		pstThread->ScheduleThread.struNalu.bufsize = length;

		frame_queue_put(&pstThread->ScheduleThread.bufQueue, &pstThread->ScheduleThread.struNalu);
//		PRINT_DBG("input data length: %d\n", length);
	}

	return 0;
}

