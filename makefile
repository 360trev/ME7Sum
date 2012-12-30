# makefile

DEBUG   =@
RM      =del
CC      =gcc
ECHO    =@echo
CFLAGS  =-Wall -O3 -D_WIN32_
LDFLAGS =

EXE     =me7sum.exe
SRC     =$(notdir $(foreach dir, ., $(wildcard $(dir)/*.c)))
LIBS    =lib_ini.dll

include makefile.common
