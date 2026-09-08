| Invoke an unimplemented syscall (nice = 34, not implemented in Task 8) to
| trigger the fail-fast diagnostic dump.
	.text
	.globl _start
_start:
	movel	#5,%sp@-           | arg1
	movel	#0,%sp@-           | dummy return address
	movew	#34,%d0           | syscall 34 = nice (unimplemented)
	trap	#0
	stop	#0x2700
