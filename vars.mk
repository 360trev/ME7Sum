RM      =rm -f
CC      =gcc
AR      =ar rcs
ECHO    =@echo
CFLAGS  =-Wall -O3 -Werror

UNAME := $(shell uname -s)
ifeq ($(findstring CYGWIN,$(UNAME)),CYGWIN)
# CFLAGS += -D_WIN32_
EXE_EXT := .exe
else
endif

SRC     =$(notdir $(foreach dir, ., $(wildcard $(dir)/*.c)))
