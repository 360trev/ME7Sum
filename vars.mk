RM      =rm -f
CC      =gcc
AR      =ar rcs
ECHO    =@echo
CFLAGS  =-Wall -O3 -Werror -MD

UNAME := $(shell uname -s)
ifeq ($(findstring CYGWIN,$(UNAME)),CYGWIN)
EXE_EXT := .exe
CC=i686-pc-mingw32-gcc
CFLAGS += -D_GNU_SOURCE=1
else
endif

SRC     =$(notdir $(foreach dir, ., $(wildcard $(dir)/*.c)))
