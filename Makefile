ifeq ($(TYPE),LINUX_X86)
DEBUG	=-DONLINUX	
FLAGS = -pthread 
CROSS_COMPILE=
endif

ifeq ($(TYPE),LINUX_ANDROID)
DEBUG	=-DONANDROID	
FLAGS = -pthread -llog
CROSS_COMPILE=arm-linux-androideabi-
endif

AS              = $(CROSS_COMPILE)as
LD              = $(CROSS_COMPILE)ld
CC              = $(CROSS_COMPILE)gcc
CPP             = $(CROSS_COMPILE)g++
AR              = $(CROSS_COMPILE)ar
NM              = $(CROSS_COMPILE)nm
STRIP           = $(CROSS_COMPILE)strip
OBJCOPY         = $(CROSS_COMPILE)objcopy
OBJDUMP         = $(CROSS_COMPILE)objdump
RANLIB          = $(CROSS_COMPILE)ranlib

STATIC_LIBS		= 	bin/librtspserver.a

OBJS:=$(patsubst src/%.c, src/%.o, $(wildcard src/*.c))
TEST_OBJ:=$(patsubst example/%.c, example/%.o, $(wildcard example/*.c))
            		
INC_PATH = -Iinclude 
CFLAGS	= $(DEBUG) $(INC_PATH)

#DEBUG	= -g -Wall

%.o:src/%.c
	$(CC)  -c  $^ -o $@	$(FLAGS)	
		
all: $(STATIC_LIBS) test

test:$(TEST_OBJ) $(STATIC_LIBS)
	$(CC) -o $@ $^ $(FLAGS) $(STATIC_LIBS)  $(LIBS)
	chmod 777 $@

$(STATIC_LIBS): $(OBJS)
	$(AR)  rcs $@ $^
clean:
	rm -f $(STATIC_LIBS) $(OBJS) $(TEST_OBJ) test


