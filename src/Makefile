#$Id: Makefile.msvc,v 1.1.1.1 2004/06/25 17:32:54 vlad Exp $
#
# 3 proxy Makefile for Microsoft Visual C compiler (for both make and nmake)
#
# You can try to add /D "WITH_STD_MALLOC" to CFLAGS to use standard malloc
# libraries

CC = cl
CFLAGS = /nologo /MT /W3 /Ox /GX /G7 /GS /GA /GF /D "WITH_STD_MALLOC" /D "NDEBUG" /D "WIN32" /D "_CONSOLE" /D "_MBCS" /D "_WIN32" /Fp"proxy.pch" /YX /FD /c
COUT = /Fo
LN = link
LDFLAGS = /nologo /subsystem:console /incremental:no /machine:I386
LIBS = ws2_32.lib advapi32.lib odbc32.lib user32.lib
LNOUT = /out:
EXESUFFICS = .exe
OBJSUFFICS = .obj
DEFINEOPTION = /D 
COMPFILES = *.pch *.idb
REMOVECOMMAND = del 2>NUL >NUL
TYPECOMMAND = type
COMPATLIBS =
MAKEFILE = Makefile.msvc

include Makefile.inc
