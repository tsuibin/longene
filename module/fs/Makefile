#
# Makefile for fs management
#

FS_OBJS	:=  fd.o \
			file.o \
			directory.o \
			change.o \
			completion.o \
			mapping.o \
			symlink.o \
			async.o	\
			token.o

$(MODULE)-objs	+= $(addprefix fs/, $(FS_OBJS))
