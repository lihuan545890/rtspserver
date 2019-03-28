
#ifndef _SCHEDULE_H_
#define _SCHEDULE_H_
#include <time.h>
#include <ctype.h>
#include <sys/types.h>
#include <math.h>
#include <stdio.h>
#include <pthread.h>
#include "rtp.h"
#include "framequeue.h"

typedef struct _play_args
{
    struct tm playback_time;                    /*�ط�ʱ��*/
    short playback_time_valid;                 /*�ط�ʱ���Ƿ�Ϸ�*/
    float start_time;                                   /*��ʼʱ��*/
    short start_time_valid;                        /*��ʼʱ���Ƿ�Ϸ�*/
    float end_time;                                     /*����ʱ��*/
} stPlayArgs;

typedef  int (*RTP_play_action)(RTP_session *pRtp, char *pData, int s32DataSize, unsigned int u32TimeStamp);


typedef struct _schedule_list
{
    int valid;/*�Ϸ��Ա�ʶ*/
    RTP_session *rtp_session;/*RTP�Ự*/
    RTP_play_action play_action;/*���Ŷ���*/
} stScheList;


typedef enum
{
    /*sender report,for transmission and reception statics from participants that are active senders*/
    SR=200,
    /*receiver report,for reception statistics from participants that are not active senders
       and in combination with SR for    active senders reporting on more than 31 sources
     */
    RR=201,
    SDES=202,/*Source description items, including CNAME,NAME,EMAIL,etc*/
    BYE=203,/*Indicates end of participation*/
    APP=204/*Application-specific functions*/
} rtcp_pkt_type;

typedef enum {
	CNAME=1,
	NAME=2,
	EMAIL=3,
	PHONE=4,
	LOC=5,
	TOOL=6,
	NOTE=7,
	PRIV=8		
} rtcp_info;

typedef struct SCHED_Thread_S
{
	unsigned char    byStop;
	int 			iMaxSched;
	int 			iCount;
	stScheList      *pstSched;
	pthread_t	    ScheduleThreadID;
	FrameQueue		bufQueue;
	StruNalu		struNalu;

} SCHED_Thread_S, *PSCHED_Thread_S;


int 	ScheduleInit(PSCHED_Thread_S pThread);
int 	ScheduleDestroy(PSCHED_Thread_S pThread);
void 	*schedule_do(void *p);
int 	schedule_add(RTP_session *rtp_session);
int 	schedule_start(int id,stPlayArgs *args);
void 	schedule_stop(int id);
int 	schedule_remove(int id);
int 	schedule_GetCount();


#endif  /* _SCHEDULE_H_ */


