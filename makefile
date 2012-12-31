include vars.mk

EXE     =me7sum$(EXE_EXT)
LIBS    =ini
SUBDIRS =lib_ini
LDFLAGS=-Llib_ini

include makefile.common
