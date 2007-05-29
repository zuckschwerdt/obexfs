## Process this file with automake to produce Makefile.in

AM_CFLAGS = -Wall -W -Wmissing-declarations -Wmissing-prototypes \
		-O2 -D_FILE_OFFSET_BITS=64 

LDADD =				-lfuse -lpthread \
				-lobexftp -lmulticobex -lbfb \
				-lbluetooth \
				@OPENOBEX_LIBS@

obexfs_SOURCES =		obexfs.c

obexautofs_SOURCES =		obexautofs.c

bin_PROGRAMS =			obexfs obexautofs
