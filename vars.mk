RM	= rm -f
AR	= ar rcs
ECHO	= @echo

#CASAN	= -fsanitize=address -fsanitize=undefined -fno-sanitize=alignment
#LASAN	= -lasan -lubsan

CFLAGS	= -Wall -O2 -g -Werror -MMD $(CASAN) $(CDEFS)
LDFLAGS = -Linifile $(LASAN) $(GMP_LINK) -lgmp -Wl,-Bdynamic

CDEFS	+= -D__GIT_VERSION=\"$(GIT_VERSION)\"

GIT_VERSION = $(shell sh -c 'git describe --tags --abbrev=4 --dirty --always')
SYS	:= $(shell gcc -dumpmachine)
#SYS	:= i686-w64-mingw32

CC	= $(SYS)-gcc
LD	= $(SYS)-gcc

SRC     = $(notdir $(foreach dir, ., $(wildcard $(dir)/*.c)))

ifneq (, $(findstring mingw, $(SYS)))
GMP_LINK = -Wl,-Bstatic
EXE_EXT = .exe
else ifneq (, $(findstring cygwin, $(SYS)))
EXE_EXT = -cyg.exe
endif
