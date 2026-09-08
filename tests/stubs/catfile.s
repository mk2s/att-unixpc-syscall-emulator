| Open /data.txt read-only, read up to 128 bytes, write them to stdout,
| close, and exit(0). Uses the trap #0 convention (num in d0, args on stack,
| dummy return address pushed just above args).
|
| Buffer and path live in .text after the code.

	.text
	.globl _start
_start:
	| fd = open("/data.txt", O_RDONLY=0)
	movel	#0,%sp@-           | arg2: flags = 0 (O_RDONLY)
	pea	path(%pc)          | arg1: path
	movel	#0,%sp@-           | dummy return addr
	movew	#5,%d0            | open
	trap	#0
	lea	12(%sp),%sp        | pop args
	movel	%d0,%d7           | save fd in d7

	| n = read(fd, buf, 128)
	movel	#128,%sp@-         | arg3: count
	pea	buf(%pc)           | arg2: buf
	movel	%d7,%sp@-          | arg1: fd
	movel	#0,%sp@-           | dummy return addr
	movew	#3,%d0            | read
	trap	#0
	lea	16(%sp),%sp
	movel	%d0,%d6           | save count in d6

	| write(1, buf, n)
	movel	%d6,%sp@-          | arg3: count
	pea	buf(%pc)           | arg2: buf
	movel	#1,%sp@-           | arg1: fd = 1
	movel	#0,%sp@-           | dummy return addr
	movew	#4,%d0            | write
	trap	#0
	lea	16(%sp),%sp

	| close(fd)
	movel	%d7,%sp@-
	movel	#0,%sp@-
	movew	#6,%d0            | close
	trap	#0
	lea	8(%sp),%sp

	| exit(0)
	movel	#0,%sp@-
	movel	#0,%sp@-
	movew	#1,%d0
	trap	#0
	stop	#0x2700

path:
	.asciz "/data.txt"
	.even
buf:
	.space 128
