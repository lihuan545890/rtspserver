#include<stdio.h>
#include "rtspserver_api.h"
#include "h264.h"

//FILE *fp = NULL;

void PrintBuffer(void *buffer, int len)
{
    unsigned char* p = (unsigned char*)buffer;
    int i;
    
    printf("[lih][%s:%d] buffer=%p len=0x%x\n", __FUNCTION__, __LINE__, buffer, len);
    for (i = 0; i < len; i += 16)
    {
        int j;
        printf("0x%04x:", i);
        for (j = 0; j < 16 && i + j < len; j++)
        {
            printf(" %02x", p[i + j]);
        }
        if (j < 16)
        {
            for ( ; j < 16; j++)
            {
                printf("   ");
            }
        }
        printf(" | ");
        for (j = 0; j < 16; j++)
        {
            char c = p[i + j];
            printf("%c", c >= 0x20 && c <= 0x7f ? c : '.');
        }
        printf("\n");
    }
    printf("\n");
}

void *readdata(void *arg)
{
	NALU_t *n;
	n = AllocNALU(8000000);
	
	OpenBitstreamFile("test.h264");

/*	fp = fopen("test1.h264", "wb");
	char buf[4];
	buf[0] = 0x00;
	buf[1] = 0x00;
	buf[2] = 0x00;
	buf[3] = 0x01;
*/	
	while(!feof(bits))
	{
//		printf("RtspSeverCount: %d\n", RtspSeverCount());
		if(RtspSeverCount() > 0)
		{
			int size=GetAnnexbNALU(n);//每执行一次，文件的指针指向本次找到的NALU的末尾，下一个位置即为下个NALU的起始码0x000001
			if(size<4)
			{
				printf("get nul error!\n");
				continue;
			}
			dump(n);
//			PrintBuffer(n->buf, 16);
//			fwrite(buf, 1, 4, fp);
//			fwrite(n->buf, 1, n->len, fp);
			if( n->nal_unit_type == 7 ||  n->nal_unit_type == 8)
			{
				PrintBuffer(n->buf, n->len);
			}
			RtspServerInputData(n->buf, n->len);
		}

	}
//	fclose(fp);
	printf("read over!!!\n");
}

int main()
{
	pthread_t thread_id;
	RtspServerInit(554);
	RtspServerStart();
	pthread_create(&thread_id, NULL, readdata, NULL);
	pthread_join(thread_id, NULL);	
	RtspServerStop();


	return 0;
}