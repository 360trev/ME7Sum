include vars.mk

EXE     =$(OBJ_DIR)/me7sum$(EXE_EXT)
LIBS    =ini
SUBDIRS =inifile

ifneq (, $(findstring mingw, $(SYS)))
LIBS += ws2_32
SRC += os/pgetopt.c
endif

include makefile.common

.PHONY: test
test: ecu-corpus/corpus.tsv
	scripts/test.sh

# corpus: fetch the private ecu-corpus submodule at its pinned commit (needs access)
# corpus-bump: move it to the ecu-corpus head (commit it yourself)
.PHONY: corpus corpus-bump
corpus ecu-corpus/corpus.tsv:
	git submodule update --init --checkout --depth 1 ecu-corpus

corpus-bump:
	git submodule update --init --checkout --remote --depth 1 ecu-corpus
	@git -C ecu-corpus log -1 --format='corpus now at %h %s'
	@git status --short ecu-corpus

.PHONY: win win-clean mingw32 mingw
# Native Windows build with nmake
# Always clean first, we don't have dependencies in nmake
# We can't use "./build.cmd clean" because of odd vcvarsall.bat behavior
win:
	$(RM) me7sum.exe *.obj
	./build.cmd

# Legacy MinGW 32-bit
mingw32:
	SYS=i686-w64-mingw32 make

# MinGW 64-bit
mingw:
	SYS=x86_64-w64-mingw32 make

INIS=sample.ini # testdata/broken/ferrari360.ini testdata/modified/8D0907551M.ini
.PHONY: zip
zip: win
	zip -j me7sum-$(GIT_VERSION).zip me7sum.exe ME7Check.exe README.md $(INIS)
