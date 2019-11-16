# tirdad
tirdad (pronounce /tērdäd/) is a kernel module to hot-patch the Linux kernel to generate random TCP Initial Sequence Numbers for outgoing IPv4 TCP connections.

You can refer to this bog post to get familiar with the original issue:

https://bitguard.wordpress.com/?p=982

# Usage
 Compile by running:
 
`$./compile.sh`

 Run as root:
 
`#./load start`

 You can also disable the module with:
 
`#./load stop`

 After you disable it, the kernel will continue to use its default algorithm to generate initial sequence numbers.
