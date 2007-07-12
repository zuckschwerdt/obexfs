## Process this file with automake to produce Makefile.in

AM_CFLAGS = -Wall -W -Wmissing-declarations -Wmissing-prototypes \
		-O2 @FUSE_CFLAGS@

LDADD =				@FUSE_LIBS@ \
				-lobexftp -lmulticobex -lbfb \
				@OPENOBEX_LIBS@ \
				-lbluetooth

obexfs_SOURCES =		obexfs.c

obexautofs_SOURCES =		obexautofs.c

bin_PROGRAMS =			obexfs obexautofs
