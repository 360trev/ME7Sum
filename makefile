include vars.mk

EXE     =me7sum$(EXE_EXT)
LIBS    =ini
SUBDIRS =lib_ini
LDFLAGS=-Llib_ini

include makefile.common

me7sum.o: me7sum.c inifile_prop.h lib_ini/inifile.h
inifile_prop.o: inifile_prop.h lib_ini/inifile.h
