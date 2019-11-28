# tirdad
tirdad (pronounce /tērdäd/) is a kernel module to hot-patch the Linux kernel to generate random TCP Initial Sequence Numbers for IPv4 TCP connections.

You can refer to this bog post to get familiar with the original issue:

https://bitguard.wordpress.com/?p=982

# Requirements
This module has been written for x86_64 architecture and will run on a Linux kernel no older than 4.14. For the build process you will need to have the correct kernel header files already installed on your system. These header files are usually available in your apt repositories.

An example installation of the header files:
```
apt-get install linux-headers-`uname -r`
```
# Usage
 Compile by running:

`$make`

 Run as root:

`#./load start`

 You can also disable the module with:

`#./load stop`

 After you disable it, the kernel will continue to use its default algorithm to generate initial sequence numbers.
