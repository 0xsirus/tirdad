build_path := /lib/modules/$(shell uname -r)/build
pwd := $(shell pwd)/module

all:
	cd module; make -C $(build_path) M=$(pwd)

clean:
	rm -r -f \
		module/tirdad.ko \
		module/modules.order \
		module/.tirdad.ko.cmd \
		module/.tirdad.mod.o.cmd \
		module/.tirdad.o.cmd \
		module/.tmp_versions \
		module/Module.symvers \
		module/tirdad.mod.c \
		module/tirdad.mod.o \
		module/tirdad.o
