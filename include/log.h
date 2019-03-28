#include<stdio.h>


#ifdef ONANDROID
#include <android/log.h>
#define TAG "RTSPSERVER"
#define PRINT_DBG(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define PRINT_ERROR(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#else 
#define PRINT_DBG(x...) do{/*printf("[%s.%d]",__FUNCTION__,__LINE__);*/printf(x);}while(0)
#define PRINT_ERROR(x...) do{/*printf("[%s.%d]",__FUNCTION__,__LINE__);*/printf(x);}while(0)
#endif
