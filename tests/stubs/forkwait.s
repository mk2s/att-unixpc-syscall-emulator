| fork(); child: exit(7); parent: wait(&status); exit((status>>8)&0xff).
| Verifies fork returns 0 in child / pid in parent, and wait reports the
| child's exit code in the status word high byte.
	.text
	.globl _start
_start:
	| pid = fork()
	movel	#0,%sp@-           | dummy return addr (fork takes no args)
	movew	#2,%d0           | fork
	trap	#0
	lea	4(%sp),%sp
	tstl	%d0
	bne	parent

child:
	| exit(7)
	movel	#7,%sp@-
	movel	#0,%sp@-
	movew	#1,%d0
	trap	#0
	stop	#0x2700

parent:
	| wait(&status) ; status stored at buf
	pea	statusbuf(%pc)     | arg1: &status
	movel	#0,%sp@-           | dummy return addr
	movew	#7,%d0           | wait
	trap	#0
	lea	8(%sp),%sp

	| load status, extract high byte of low word: (status>>8)&0xff
	movel	statusbuf(%pc),%d1
	lsrl	#8,%d1
	andil	#0xff,%d1

	| exit(d1)
	movel	%d1,%sp@-
	movel	#0,%sp@-
	movew	#1,%d0
	trap	#0
	stop	#0x2700

statusbuf:
	.long 0
