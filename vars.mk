RM	= rm -f
CC	= gcc
AR	= ar rcs
ECHO	= @echo
CFLAGS	= -Wall -O3 -Werror -MD $(CDEFS)

CDEFS	+= -D__GIT_VERSION=\"$(GIT_VERSION)\"

UNAME       = $(shell uname -s)
GIT_VERSION = $(shell sh -c 'git describe --abbrev=4 --dirty --always')

ifeq ($(findstring CYGWIN,$(UNAME)),CYGWIN)
EXE_EXT = .exe
CC	= i686-pc-mingw32-gcc
CDEFS	+= -D_GNU_SOURCE=1
endif

SRC     = $(notdir $(foreach dir, ., $(wildcard $(dir)/*.c)))
