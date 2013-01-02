include vars.mk

EXE     =me7sum$(EXE_EXT)
LIBS    =ini
SUBDIRS =inifile
LDFLAGS=-Linifile

include makefile.common

me7sum.c: crc32.h utils.h inifile_prop.h inifile/inifile.h
inifile_prop.c: inifile_prop.h inifile/inifile.h
crc32.c: crc32.h
utils.c: utils.h load_file.h save_file.h
load_file.c: load_file.h
save_file.c: save_file.h
