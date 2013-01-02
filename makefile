include vars.mk

EXE     =me7sum$(EXE_EXT)
LIBS    =ini
SUBDIRS =lib_ini
LDFLAGS=-Llib_ini

include makefile.common

me7sum.o: me7sum.c crc32.h utils.h inifile_prop.h lib_ini/inifile.h
inifile_prop.o: inifile_prop.h lib_ini/inifile.h
crc32.o: crc32.h
utils.o: utils.h
