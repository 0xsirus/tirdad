build_path := /lib/modules/$(shell uname -r)/build
pwd := $(shell pwd)/module

all:
	gcc -oload load.c
	@echo $(build_path)
	cd module; 	make -C $(build_path) M=$(pwd)
	
clean:
	rm load module/tirdad
