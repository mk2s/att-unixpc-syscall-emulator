| sbrk(4096) -> a0 (old break). Write 0x12345678 at a0. Read it back into d1.
| write a marker byte to stdout to show liveness, then exit(0).
	.text
	.globl _start
_start:
	| p = sbrk(4096)
	movel	#4096,%sp@-        | arg1: incr
	movel	#0,%sp@-           | dummy return addr
	movew	#17,%d0           | sbrk
	trap	#0
	lea	8(%sp),%sp
	movel	%d0,%a0           | a0 = old break (new memory)

	| *(long*)a0 = 0x12345678
	movel	#0x12345678,%a0@

	| exit( *(long*)a0 == 0x12345678 ? 7 : 9 )
	movel	%a0@,%d1
	cmpil	#0x12345678,%d1
	bne	fail
	movel	#7,%sp@-
	bra	doexit
fail:
	movel	#9,%sp@-
doexit:
	movel	#0,%sp@-
	movew	#1,%d0
	trap	#0
	stop	#0x2700
