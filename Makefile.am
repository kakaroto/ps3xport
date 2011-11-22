# Makefile.am for ps3tools
#
# (C) Youness Alaoui (KaKaRoTo)
#
# Licensed under LGPL 2.1. See file COPYING.

ERROR_CFLAGS = \
	$(PS3TOOLS_CFLAGS) \
	-fno-strict-aliasing \
	-Wextra \
	-Wundef \
	-Wnested-externs \
	-Wwrite-strings \
	-Wpointer-arith \
	-Wbad-function-cast \
	-Wmissing-declarations \
	-Wmissing-prototypes \
	-Wstrict-prototypes \
	-Wredundant-decls \
	-Wno-unused-parameter \
	-Wno-missing-field-initializers

AM_CFLAGS = \
	$(ERROR_CFLAGS)

bin_PROGRAMS = 	ps3xport

ps3xport_SOURCES =  types.h \
		tools.c \
		tools.h \
		aes.c \
		aes.h \
		sha1.c \
		sha1.h \
		ps3xport.c \
		paged_file.c
