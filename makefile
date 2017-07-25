# FOR MSVSS nmake only

TARGET = me7sum.exe
SOURCES = crc32.c inifile_prop.c me7sum.c utils.c str.c range.c inifile/inifile.c os/pgetopt.c rsa.c md5.c
LIBRARIES = Ws2_32.lib mpir/mpir.lib

CFLAGS = -D__GIT_VERSION=\"$(GIT_VERSION)\"

all: $(TARGET)
$(TARGET):$(SOURCES)
	cl /EHsc /Fe$@ $(CFLAGS) /Tc $(SOURCES) $(LIBRARIES)

clean:
	del $(TARGET) *.obj
