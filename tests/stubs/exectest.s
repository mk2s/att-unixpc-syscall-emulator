| execve("/hello", argv, envp) — replace self with the hello program.
| If exec returns, it failed: exit(99).
	.text
	.globl _start
_start:
	pea	envp(%pc)          | arg3: envp
	pea	argv(%pc)          | arg2: argv
	pea	path(%pc)          | arg1: path
	movel	#0,%sp@-           | dummy return addr
	movew	#59,%d0          | execve
	trap	#0
	lea	16(%sp),%sp        | (only reached on failure)

	| exec failed
	movel	#99,%sp@-
	movel	#0,%sp@-
	movew	#1,%d0
	trap	#0
	stop	#0x2700

path:
	.asciz "/hello"
	.even
arg0:
	.asciz "hello"
	.even
argv:
	.long arg0
	.long 0
envp:
	.long 0
