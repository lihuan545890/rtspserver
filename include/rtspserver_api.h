#include <pthread.h>

int RtspServerInit(int port);
int RtspServerStart();
int RtspServerStop();
int RtspServerDestroy();
int RtspSeverCount();
int RtspServerInputData(unsigned char* data, int length);

