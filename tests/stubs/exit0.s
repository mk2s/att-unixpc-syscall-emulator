	.text
	.globl _start
_start:
	movel	#0,%sp@-
	movel	#0,%sp@-
	movew	#1,%d0
	trap	#0
	stop	#0x2700
