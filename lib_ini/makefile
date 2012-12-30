# makefile

DEBUG   =@
RM      =del
CC      =gcc
ECHO    =@echo
CFLAGS  =-Wall -O3 -D_WIN32_
LDFLAGS =-s -shared

EXE     =lib_ini.dll
SRC     =$(notdir $(foreach dir, ., $(wildcard $(dir)/*.c)))
LIBS    =

include makefile.common
