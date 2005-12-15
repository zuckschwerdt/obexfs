## Process this file with automake to produce Makefile.in

LDADD =				-lfuse -lpthread \
				@OPENOBEX_LIBS@ \
				-lbluetooth \
				-lobexftp -lmulticobex -lbfb

obexfs_SOURCES =		obexfs.c

obexautofs_SOURCES =		obexautofs.c

bin_PROGRAMS =			obexfs obexautofs
