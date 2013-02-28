#
# Makefile for kernel execute
#

KE_OBJS		+= wait.o \
		   misc.o \
		   binfmt_pe.o \
		   binfmt_exeso.o \
		   apc.o \
		   unistr.o \
		   wcstr.o \
		   switch.o \
		   w32syscall.o \
		   w32entry.o \
		   w32init.o \
		   sysdll.o \
		   event.o \
		   mutex.o \
		   semaphore.o \
		   proc.o

$(MODULE)-objs	+= $(addprefix ke/, $(KE_OBJS))
