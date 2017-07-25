RM	= rm -f
AR	= ar rcs
ECHO	= @echo

#CASAN	= -fsanitize=address -fsanitize=undefined -fno-sanitize=alignment
#LASAN	= -lasan -lubsan

CFLAGS	= -Wall -O2 -g -Werror -MMD $(CASAN) $(CDEFS)
LDFLAGS = -Linifile $(LASAN) -lgmp

CDEFS	+= -D__GIT_VERSION=\"$(GIT_VERSION)\"

GIT_VERSION = $(shell sh -c 'git describe --tags --abbrev=4 --dirty --always')
SYS	:= $(shell gcc -dumpmachine)

ifneq (, $(findstring mingw, $(SYS)))
EXE_EXT = .exe
else ifneq (, $(findstring cygwin, $(SYS)))
EXE_EXT = .exe
endif

CC	= $(SYS)-gcc
LD	= $(SYS)-gcc

SRC     = $(notdir $(foreach dir, ., $(wildcard $(dir)/*.c)))
