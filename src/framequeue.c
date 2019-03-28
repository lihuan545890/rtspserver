#ifdef __cplusplus
extern "C" {

#endif /* __cplusplus */

#include <stdio.h>
#include <string.h>
#include <pthread.h>

#include "framequeue.h"
#include "log.h"

int frame_queue_init(FrameQueue *q)
{
    memset(q, 0, sizeof(FrameQueue));

	pthread_mutex_init(&q->mutex, NULL);
	pthread_cond_init(&q->cond, NULL); 
    q->abort_request = 1;

    return 0;
}

void frame_queue_destroy(FrameQueue *q)
{
    frame_queue_flush(q);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->cond);
}

static int frame_queue_put_private(FrameQueue *q, StruNalu *frame)
{
    MyAVFrameList *frame1;

    if (q->abort_request)
       return -1;

    frame1 = malloc(sizeof(MyAVFrameList));
    if (!frame1)
    {
       PRINT_DBG("malloc failed");
       return -1;
    }
 
    frame1->buffer = *frame;
    frame1->next = NULL;


    if (!q->last_frame)
    {
        q->first_frame = frame1;
     
    }
    else
    {
        q->last_frame->next = frame1;
      
    }

    q->last_frame = frame1;
    q->nb_packets++;
    
    /* XXX: should duplicate packet data in DV case */
    pthread_cond_signal(&q->cond);
    return 0;
}

int frame_queue_put(FrameQueue *q, StruNalu *frame)
{
    int ret;

    pthread_mutex_lock(&q->mutex);
    ret = frame_queue_put_private(q, frame);
    pthread_mutex_unlock(&q->mutex);

    if (ret < 0)
        free(frame->pNalu);

    return ret;
}


void frame_queue_flush(FrameQueue *q)
{
    MyAVFrameList *frame, *frame1;

    pthread_mutex_lock(&q->mutex);
    for (frame = q->first_frame; frame; frame = frame1) {
        frame1 = frame->next;
        free(frame->buffer.pNalu);
        free(frame);
    }
    q->last_frame = NULL;
    q->first_frame = NULL;
    q->nb_packets = 0;
    pthread_mutex_unlock(&q->mutex);
}

void frame_queue_abort(FrameQueue *q)
{
    pthread_mutex_lock(&q->mutex);

    q->abort_request = 1;

    pthread_cond_signal(&q->cond);

    pthread_mutex_unlock(&q->mutex);
}

void frame_queue_start(FrameQueue *q)
{
    pthread_mutex_lock(&q->mutex);
    q->abort_request = 0;
    pthread_mutex_unlock(&q->mutex);
}

int  frame_queue_count(FrameQueue *q)
{
	int count = 0;

	pthread_mutex_lock(&q->mutex);
    count = q->nb_packets;
    pthread_mutex_unlock(&q->mutex);

	return count;
}


/* return < 0 if aborted, 0 if no packet and > 0 if packet.  */
int frame_queue_get(FrameQueue *q, StruNalu *frame, int block)
{
    MyAVFrameList *frame1;
    int ret;

    pthread_mutex_lock(&q->mutex);

    for (;;) {
        if (q->abort_request) {
            ret = -1;
            break;
        }
		
        frame1 = q->first_frame;
        if (frame1) {
            q->first_frame = frame1->next;
            if (!q->first_frame)
                q->last_frame = NULL;
            q->nb_packets--;
            *frame = frame1->buffer;

            free(frame1);
            ret = 1;
      //      LOGI("get buffer: %x, size: %d", frame->frame, frame->bufsize);
            break;
        } else if (!block) {
            ret = 0;
            break;
        } else {
    //    	PRINT_DBG("pthread_cond_wait!!!");
            pthread_cond_wait(&q->cond, &q->mutex);
        }
    }
    pthread_mutex_unlock(&q->mutex);

//    LOGI("get queue ret : %d", ret);
    return ret;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */


