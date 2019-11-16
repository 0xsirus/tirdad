#!/bin/bash

gcc -oload load.c
make -C /lib/modules/$(uname -r)/build M=$(pwd)
