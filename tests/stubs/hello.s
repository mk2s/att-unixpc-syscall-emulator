| write(1, msg, len) then exit(0), using the trap #0 convention.
| The message lives in .text right after the code (we assemble a single
| blob and place msg at a known offset patched via a PC-relative lea).

	.text
	.globl _start
_start:
	| write(1, msg, 6)
	lea	msg(%pc),%a0        | a0 = &msg
	movel	#6,%sp@-           | arg3: len = 6
	movel	%a0,%sp@-          | arg2: buf = &msg
	movel	#1,%sp@-           | arg1: fd = 1
	movel	#0,%sp@-           | dummy return address
	movew	#4,%d0            | syscall 4 = write
	trap	#0
	lea	16(%sp),%sp        | pop the 4 pushed longs

	| exit(0)
	movel	#0,%sp@-           | arg1: status = 0
	movel	#0,%sp@-           | dummy return address
	movew	#1,%d0            | syscall 1 = exit
	trap	#0
	stop	#0x2700

msg:
	.ascii "hello\n"
	.even
