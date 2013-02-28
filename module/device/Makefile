#
# Makefile for device management
#

DEVICE_OBJS	:=  clipboard.o \
				console.o \
				named_pipe.o \
				mailslot.o \
				device.o \
				timer.o \
				snapshot.o \
				serial.o

$(MODULE)-objs	+= $(addprefix device/, $(DEVICE_OBJS))
