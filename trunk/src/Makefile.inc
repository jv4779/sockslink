#$Id: Makefile.inc,v 1.6 2005/05/06 09:35:05 vlad Exp $
#
# 3 proxy common Makefile
#


all:	pre socks$(EXESUFFICS)

pre:
	$(PREMAKE)

sockmap$(OBJSUFFICS): sockmap.c proxy.h
	$(CC) $(CFLAGS) sockmap.c

common$(OBJSUFFICS): common.c proxy.h
	$(CC) $(CFLAGS) common.c

myalloc$(OBJSUFFICS): myalloc.c proxy.h
	$(CC) $(CFLAGS) myalloc.c

sockgetchar$(OBJSUFFICS): sockgetchar.c proxy.h
	$(CC) $(CFLAGS) sockgetchar.c

socks$(OBJSUFFICS): socks.c proxy.h proxymain.c
	$(CC) $(CFLAGS) $(DEFINEOPTION)WITHMAIN $(DEFINEOPTION)NOPORTMAP socks.c

socks$(EXESUFFICS): sockmap$(OBJSUFFICS) socks$(OBJSUFFICS) sockgetchar$(OBJSUFFICS) myalloc$(OBJSUFFICS) common$(OBJSUFFICS)
	$(LN) $(LNOUT)socks$(EXESUFFICS) $(LDFLAGS) $(VERFILE) sockmap$(OBJSUFFICS) socks$(OBJSUFFICS) sockgetchar$(OBJSUFFICS)  myalloc$(OBJSUFFICS) common$(OBJSUFFICS) $(LIBS)

stringtable$(OBJSUFFICS):  stringtable.c
	$(CC) $(COUT)stringtable$(OBJSUFFICS) $(CFLAGS) stringtable.c

clean:
	@$(REMOVECOMMAND) *$(OBJSUFFICS) $(COMPFILES)
