@echo off
del XPLoginLogger.dll
c:\masm32\BIN\ml.exe /c /coff /nologo /Cp XPLoginLogger.asm
c:\masm32\BIN\Link.exe /SECTION:.text,EWR /SECTION:.bss,S /DLL /DEF:XPLoginLogger.def /SUBSYSTEM:WINDOWS /LIBPATH:c:\masm32\lib XPLoginLogger.obj
copy XPLoginLogger.dll ..\
pause
