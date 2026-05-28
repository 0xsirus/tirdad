ifneq ($(KERNELRELEASE),)
	KERNELDIR ?= /lib/modules/$(KERNELRELEASE)/build
else
	## KERNELRELEASE not set.
	KERNELDIR ?= /lib/modules/$(shell uname -r)/build
endif

pwd := $(shell pwd)/module

all:
	@echo "KERNELDIR: $(KERNELDIR)"
	cd module; make -C $(KERNELDIR) M=$(pwd)
	cd evaluator; gcc -orun -Wno-varargs evaluator.c -pthread

clean:
	rm -r -f \
		module/tirdad.ko \
		module/modules.order \
		module/.tirdad.ko.cmd \
		module/.tirdad.mod.o.cmd \
		module/.tirdad.o.cmd \
		module/.tirdad.o.d \
		module/.tmp_versions \
		module/Module.symvers \
		module/tirdad.mod*\
		module/..module* \
		module/.module* \
		module/.Module* \
		module/.tirdad* \
		module/tirdad.o \
		evaluator/run
