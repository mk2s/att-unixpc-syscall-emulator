| pipe(fds); fork(); child writes 'Z' to fds[1]; parent reads 1 byte from
| fds[0] into buf and exits(buf[0]). Verifies pipe + fork cooperation.
|
| pipe() returns read fd in D0, write fd in D1 (SVR convention).
	.text
	.globl _start
_start:
	| pipe(): d0=readfd, d1=writefd
	movel	#0,%sp@-           | dummy return addr (pipe takes fds ptr on real
	                           | SVR, but our impl returns in d0/d1)
	movew	#42,%d0          | pipe
	trap	#0
	lea	4(%sp),%sp
	movel	%d0,%d5           | d5 = read fd
	movel	%d1,%d6           | d6 = write fd

	| pid = fork()
	movel	#0,%sp@-
	movew	#2,%d0           | fork
	trap	#0
	lea	4(%sp),%sp
	tstl	%d0
	bne	parent

child:
	| write(d6, msg, 1)   msg = 'Z'
	movel	#1,%sp@-           | count
	pea	msg(%pc)           | buf
	movel	%d6,%sp@-          | fd = write end
	movel	#0,%sp@-           | dummy retaddr
	movew	#4,%d0           | write
	trap	#0
	lea	16(%sp),%sp
	| exit(0)
	movel	#0,%sp@-
	movel	#0,%sp@-
	movew	#1,%d0
	trap	#0
	stop	#0x2700

parent:
	| read(d5, buf, 1)
	movel	#1,%sp@-           | count
	pea	buf(%pc)           | buf
	movel	%d5,%sp@-          | fd = read end
	movel	#0,%sp@-           | dummy retaddr
	movew	#3,%d0           | read
	trap	#0
	lea	16(%sp),%sp

	| exit(buf[0])
	moveq	#0,%d1
	moveb	buf(%pc),%d1
	movel	%d1,%sp@-
	movel	#0,%sp@-
	movew	#1,%d0
	trap	#0
	stop	#0x2700

msg:
	.ascii "Z"
	.even
buf:
	.long 0
