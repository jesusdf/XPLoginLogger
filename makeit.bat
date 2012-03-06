@echo off
del XPLoginLogger.exe
c:\masm32\BIN\ml.exe /c /coff /nologo /Cp XPLoginLogger.asm
c:\masm32\BIN\Link.exe /SECTION:.text,EWR /RELEASE /SUBSYSTEM:WINDOWS /LIBPATH:\masm32\lib XPLoginLogger.obj
pause
