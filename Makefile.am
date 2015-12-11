# Makefile.am for ps3xport
# Licensed under GPL v3. See file COPYING.

ERROR_CFLAGS = \
	$(PS3XPORT_CFLAGS) \
	-fno-strict-aliasing \
	-Wall \
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
		keys.c \
		keys.h \
		aes.c \
		aes.h \
		sha1.c \
		sha1.h \
		ps3xport.c \
		archive.c \
		vtrm.c \
		paged_file.c
