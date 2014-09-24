# FOR MSVSS nmake only

TARGET = me7sum.exe
SOURCES = crc32.c inifile_prop.c me7sum.c utils.c str.c inifile/inifile.c os/pgetopt.c
CFLAGS = -D__GIT_VERSION=\"$(GIT_VERSION)\"

all: $(TARGET)
$(TARGET):$(SOURCES)
	cl /EHsc /Fe$@ $(CFLAGS) /Tc $(SOURCES)

clean:
	del $(TARGET) *.obj
