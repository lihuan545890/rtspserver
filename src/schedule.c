#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <sys/time.h>

#include "schedule.h"
#include "rtsp.h"
#include "rtp.h"
#include "log.h"

#define MAX_MEDIA_TYPE  1
#define MAX_HEAD_LEN    100
#define MAX_VIDEO_PKT_LEN  1400


static stScheList *sched=NULL;
static int iMaxConnect=0;
static int iCount=0;
pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

int ScheduleInit(PSCHED_Thread_S pThread)
{
    int i;
	pThread->pstSched=malloc(sizeof(stScheList)*pThread->iMaxSched);
	if(!pThread->pstSched)
	{
		return -1;
	}
	
	sched=pThread->pstSched;
	iMaxConnect=pThread->iMaxSched;
	
    /*初始化数据*/
    for (i=0; i<iMaxConnect; ++i)
    {
        sched[i].rtp_session=NULL;
        sched[i].play_action=NULL;
        sched[i].valid=0;
    }
    return 0;
}



int ScheduleDestroy(PSCHED_Thread_S pThread)
{
	
	free(pThread->pstSched);
	sched=NULL;
	iMaxConnect=0;

    return 0;
}


void schedule_SendVideo(int index,StruNalu* pstNalu)
{
	int i=0,iNalu=0,iNaluLen=0;
	char *pNalu=NULL;
	struct timeval now;
	unsigned int mnow;
	
//	mnow=(pstVideoFrame->dwSecStamp)*1000+pstVideoFrame->dwMilStamp;

	//for(iNalu=0;iNalu<pstVideoFrame->byNaluCount;iNalu++)
	{

	//	pNalu=pstVideoNode->pszData+sizeof(STVIDEOFRAMEINFO)
	//		+pstVideoFrame->stNaluInfo[iNalu].dwNaluPos+4;//去掉四个分割符 00 00 00 01
		
	//	iNaluLen=pstVideoFrame->stNaluInfo[iNalu].dwNaluLen-4;
	
		for (i=0; i<iMaxConnect; i++)
		{
	
			if(sched[i].valid)
			{
//				PRINT_DBG("video index: %d, index: %d\n",sched[i].rtp_session->videoIndex, index );
				if(!sched[i].rtp_session->pause&& sched[i].rtp_session->videoIndex==index)
				{
					
					if(sched[i].rtp_session->emPayload==_h264)
					{
						gettimeofday(&now, NULL);
						mnow = (now.tv_sec*1000 + now.tv_usec/1000);
						//PRINT_DBG("bufsize: %d", pstNalu->bufsize);
						if(sched[i].play_action(sched[i].rtp_session, pstNalu->pNalu+4,pstNalu->bufsize-4, mnow)<0)
						{
							RTSP_buffer * pRtsp=NULL;
							sched[i].rtp_session->pause=1;//此处将发生错误的rtp_session暂停住，而不销毁，交由rtsp来决定销毁
							pRtsp=(RTSP_buffer *)(sched[i].rtp_session->pRtsp);
							pRtsp->iNeedClose=1;
							PRINT_DBG("some error happen !close rtsp\n");
						}
					}
					
				}
			}
		}
	}
}

#if 0
void schedule_SendAudio(int index,PBUFNODE pstAudioNode)
{

	int i=0;
	unsigned int  mnow;
	
	PSTAUDIOFRAMEINFO pstAudioFrame=(PSTAUDIOFRAMEINFO)pstAudioNode->pszData;
	mnow=(pstAudioFrame->dwSecStamp)*1000+pstAudioFrame->dwMilStamp;
	
	char *pAudio=pstAudioNode->pszData+sizeof(STAUDIOFRAMEINFO);
		
	for (i=0; i<iMaxConnect; i++)
	{
		if(sched[i].valid)
		{
			//printf("sched[i].valid=1**********************************\n");
			if(!sched[i].rtp_session->pause)
			{
				if(sched[i].rtp_session->emPayload==_g711)
				{
					if(sched[i].play_action(sched[i].rtp_session, pAudio, pstAudioFrame->nDataLen, mnow)<0)
					{
						RTSP_buffer * pRtsp=NULL;
						sched[i].rtp_session->pause=1;//此处将发生错误的rtp_session暂停住，而不销毁，交由rtsp来决定销毁
						pRtsp=(RTSP_buffer *)(sched[i].rtp_session->pRtsp);
						pRtsp->iNeedClose=1;
						mydebug("some error happen !close rtsp\n");
					}
				}
			}
		}
	}
}
#endif

void *schedule_do(void *p)
{
    int i=0;
	unsigned int dwCurMdaIndex[MAX_MEDIA_TYPE];
	char*     pstBufNode=NULL;
	unsigned char byGetMda=0;
	//90000/framerate
	FILE *fp=NULL;
	fp = fopen("/sdcard/test1.h264", "wb+");
/*	char buf[4];
	buf[0] = 0x00;
	buf[1] = 0x00;
	buf[2] = 0x00;
	buf[3] = 0x01;	*/
	PSCHED_Thread_S pThread=(PSCHED_Thread_S)p;
	while (!pThread->byStop)
	{	
		for (i=0; i<iMaxConnect; ++i)
		{
			if (!sched[i].valid && sched[i].rtp_session)
			{
				//printf("rtp session not valid, but still present...\n");
				PRINT_DBG("remove rtp session now!>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n");
				RTP_session_destroy(sched[i].rtp_session);							   /*删除会话*/
				sched[i].rtp_session = NULL;
				sched[i].play_action=NULL;
			}
		}

		if(iCount<=0)
		{
			msleep(50);
		/*	
			for(i=0;i<MAX_MEDIA_TYPE;i++)
			{
				dwCurMdaIndex[i]=HL_GetPreNodeIndex(&g_stmediaBuff[i],g_stmediaBuff[i].iWriteIndex);
			}
		*/	
			continue;
		}

		byGetMda=0;
		for(i=0;i<MAX_MEDIA_TYPE;i++)
		{			
			int ret = frame_queue_get(&pThread->bufQueue, &pThread->struNalu, 1);
//			fwrite(buf, 1, 4, fp);
//			fwrite(pThread->struNalu.pNalu, 1, pThread->struNalu.bufsize, fp);			
			if(iCount>0)
			//if(!HL_GetBufArrayNode(&g_stmediaBuff[i],&pstBufNode,dwCurMdaIndex[i]))
			{
				byGetMda=1;
				switch(i)
				{
					case 0:
					case 1:
						PRINT_DBG("send video buffer bufsize:%d", pThread->struNalu.bufsize);
						schedule_SendVideo(i,&pThread->struNalu);
						break;
					case 2:
					//	schedule_SendAudio(i,pstBufNode);
						break;
				}
				
				//HL_ReleaseBuffNode(&g_stmediaBuff[i],pstBufNode);
				//dwCurMdaIndex[i]=HL_GetNextNodeIndex(&g_stmediaBuff[i],dwCurMdaIndex[i]);	
			}
		}

		if(!byGetMda)
		{
			msleep(8);
		}
		else
		{
			msleep(5);
		}

	} 

	return ERR_NOERROR;
}





int schedule_add(RTP_session *rtp_session)
{
	pthread_mutex_lock(&g_mutex);
    int i;
    for (i=0; i<iMaxConnect; ++i)
    {
        /*需是还没有被加入到调度队列中的会话*/
        if (!sched[i].valid)
        {
        	sched[i].valid=1;
        	sched[i].rtp_session=rtp_session;

        	//设置播放动作
			sched[i].play_action=RtpSend;
			PRINT_DBG("**adding a schedule object action id=%d**\n", i);
			iCount++;
            return i;
        }
		
    }
	pthread_mutex_unlock(&g_mutex);    
    return ERR_GENERIC;
}

int schedule_GetCount()
{
    return iCount;
}


int schedule_start(int id,stPlayArgs *args)
{
	printf("schedule_start id=%d\n",id);
	sched[id].rtp_session->pause=0;
	sched[id].rtp_session->started=1;

    return ERR_NOERROR;
}

void schedule_stop(int id)
{
//    RTCP_send_packet(sched[id].rtp_session,SR);
//    RTCP_send_packet(sched[id].rtp_session,BYE);
}

int schedule_remove(int id)
{
    sched[id].valid=0;
	iCount--;
	PRINT_DBG("RTP session count=%d-----------------------------\n",iCount);
	return ERR_NOERROR;
}


