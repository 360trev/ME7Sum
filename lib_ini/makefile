# makefile

DEBUG   =@
RM      =rm -f
CC      =gcc
ECHO    =@echo
CFLAGS  =-Wall -O3 -D_WIN32_ -Werror
LDFLAGS =-s -shared

EXE     =lib_ini.dll
SRC     =$(notdir $(foreach dir, ., $(wildcard $(dir)/*.c)))
LIBS    =

include makefile.common
