@echo off
SET VSVER=10.0

IF "%PROGRAMFILES(X86)%"=="" (
  GOTO x86
) ELSE (
  GOTO amd64
)

:amd64
SET PROGPATH=%PROGRAMFILES(X86)%
GOTO Common

:x86
SET PROGPATH=%PROGRAMFILES%
GOTO Common

:Common
CALL "%PROGPATH%\Microsoft Visual Studio %VSVER%\VC\vcvarsall.bat" x86
