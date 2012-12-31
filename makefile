# makefile

DEBUG   =@
RM      =rm -f
CC      =gcc
ECHO    =@echo
CFLAGS  =-Wall -O3 -D_WIN32_ -Werror
LDFLAGS =

EXE     =me7sum.exe
SRC     =$(notdir $(foreach dir, ., $(wildcard $(dir)/*.c)))
LIBS    =lib_ini/lib_ini.dll
SUBDIRS =lib_ini

include makefile.common
