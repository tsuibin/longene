#
# Makefile for unified kernel module in the top level directory
# 

SUB_DIRS:= ke/ \
	   io/ \
	   ob/ \
	   ps/ \
	   mm/ \
	   pub/ \
	   reg/ \
	   msg/ \
	   fs/ \
	   sock/ \
	   device/

MODULE	 = unifiedkernel
MOD_O	 = $(MODULE).o
MOD_KO	 = $(MODULE).ko
MOD_MOD	 = $(MODULE).mod
KERNEL_VER = `uname -r`
MKFILES	 = $(addprefix $(PWD)/, $(addsuffix Makefile, $(SUB_DIRS)))

ifneq ($(KERNELRELEASE),)
include $(MKFILES)
	obj-m		:= $(MODULE).o
else
	KDIR		:= /lib/modules/$(KERNEL_VER)/build
	PWD		:= `pwd`

	
default:
	$(MAKE) -Wall -C $(KDIR) SUBDIRS=$(PWD) EXTRA_CFLAGS="-I$(PWD)/include" modules

clean:
	@echo CLEANING: Module files
	@rm -rf $(MOD_O) .$(MOD_O).cmd \
	       $(MOD_KO) .$(MOD_KO).cmd \
	       $(MOD_MOD).c $(MOD_MOD).o .$(MOD_MOD).o.cmd\
	       .tmp_versions Module.* modules.*
	       
	@echo CLEANING: object files
	@rm -f $(addsuffix *.o, $(SUB_DIRS))
	@rm -f $(addsuffix *.ko, $(SUB_DIRS))
	@rm -f $(addsuffix .*.o.cmd, $(SUB_DIRS))
	@echo make clean done!

endif

