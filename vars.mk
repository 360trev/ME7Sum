RM	= rm -f
AR	= ar rcs
ECHO	= @echo

#CASAN	= -fsanitize=address -fsanitize=undefined -fno-sanitize=alignment
#LASAN	= -lasan -lubsan

CFLAGS	+= -Wall -O2 -g -Werror -MD $(CASAN) $(CDEFS)

CDEFS	+= -D__GIT_VERSION=\"$(GIT_VERSION)\"

GIT_VERSION = $(shell sh -c 'git describe --tags --abbrev=4 --dirty --always')
SYS	?= $(shell gcc -dumpmachine)

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
CC	= gcc
LD	= gcc
LDFLAGS += -L /opt/homebrew/lib -Linifile $(LASAN) $(GMP_LINK) -lgmp -Wl,-dynamic
CFLAGS  += -I /opt/homebrew/include
else
CC	= $(SYS)-gcc
LD	= $(SYS)-gcc
GMP	?=gmp
LDFLAGS += -Linifile/$(OBJ_DIR) $(LASAN) $(GMP_LINK) -l$(GMP) -Wl,-Bdynamic
endif

SRC	= $(notdir $(foreach dir, ., $(wildcard $(dir)/*.c)))

ifneq (, $(findstring mingw, $(SYS)))
GMP_LINK = -Wl,-Bstatic
EXE_EXT = .exe
ifeq ($(UNAME_S),Linux)
# Use our prebuilt libgmp libraries in mpir/
GMP=gmp-$(SYS)
LDFLAGS += -Lmpir
endif
else ifneq (, $(findstring cygwin, $(SYS)))
EXE_EXT = .exe
endif
