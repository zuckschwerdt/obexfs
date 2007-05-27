## Process this file with automake to produce Makefile.in

LDADD =				-lfuse -lpthread \
				-lobexftp -lmulticobex -lbfb \
				-lbluetooth \
				@OPENOBEX_LIBS@

obexfs_SOURCES =		obexfs.c

obexautofs_SOURCES =		obexautofs.c

bin_PROGRAMS =			obexfs obexautofs
