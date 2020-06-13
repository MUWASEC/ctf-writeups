bits 64

%macro clear 1
	xor %1, %1
%endmacro

%macro clear_gprs 0
	clear rax
	clear rbx
	clear rcx
	clear rdx
	clear rsi
	clear rdi
	clear r8
	clear r9
	clear r10
	clear r11
	clear r12
	clear r13
	clear r14
	clear r15
%endmacro

%macro raw_read 2
	push qword[STDIN]
	pop rdi
	lea rsi,[%1]
	mov rdx,%2
	push qword[SYS_READ]
	pop rax
	syscall
%endmacro

%macro print 1
	push qword[STDOUT]
	pop rdi
	lea rsi,[%1]
	xor rdx,rdx
	%%len_loop:
		mov al, byte[rsi]
		test al, al
		je %%null_byte
		inc rdx
		inc rsi
	jmp %%len_loop
	%%null_byte:
	sub rsi,rdx
	push qword[SYS_WRITE]
	pop rax
	syscall
%endmacro

%macro exit 0
	push qword[SYS_EXIT]
	pop rax
	syscall
%endmacro

%macro exit_failure 0
	clear_gprs
	push qword[EXIT_FAILURE]
	pop rdi
	exit
%endmacro

%macro exit_success 0
	clear_gprs
	push qword[EXIT_SUCCESS]
	pop rdi
	exit
%endmacro

%macro sleep 2
	clear_gprs
	sub rsp, 16
	mov qword[rsp], %1
	mov qword[rsp+8],%2
	mov rdi, rsp
	push qword[SYS_NANOSLEEP]
	pop rax
	syscall
	add rsp, 16
%endmacro

section .ddd progbits alloc exec write align=16
	;; our data section
	kkk:
		db "",0x1b,"[0;94;49m|  '    |    |          '    |    |      /~\|           |          |         ",0xa,"|  |/~~||/~\~|~\    //~/|/~~||/~\~|~    -|- |/~~|/~~|/~~|/~\ /~//~~|_//~/|/~\",0xa,"|__|\__||   ||  \/\/ \/_|\__||   ||      |  |\__|\__|\__|   |\/_\__| \\/_|   ",0xa,"    \__|                 \__|                    \__|                        ",0xa,"",0x1b,"[0m", \
		"Enter your code > ", 0
	mmm:
		db 29, 17, 28, 27, 26, 18, 14, 9, 1, 30, 25, 21, 11, 2, 24, 8, 5, 22, 31, 15, 19, 7, 16, 20, 23, 0, 10, 4, 13, 12, 6, 3
	nnn:
		db 0xa5, 0xa3, 0xdc, 0xd3, 0xc0, 0xe7, 0xbe, 0xda, 0x64, 0xe0, 0xc9, 0xc4, 0xc0, 0xe7, 0xcb, 0xa1, 0xa3, 0xa3, 0xdf, 0xcc, 0xcf, 0xcd, 0x60, 0xe0, 0xdc, 0xd3, 0xc3, 0xd5, 0xdb, 0x98, 0xcd, 0xca
	aaa:
		times 33 db 0 ;; flag is 32 bytes long, plus the newline
	ooo:
		db 0xc1, 0xcc, 0xb0, 0xd, 0x9b
	iii:
		db 0xa,0xa,"",0x1b,"[0;92;49m..%%%%...%%..%%...%%%%....%%%%...%%%%%%...%%%%....%%%%..",0xa,".%%......%%..%%..%%..%%..%%..%%..%%......%%......%%.....",0xa,"..%%%%...%%..%%..%%......%%......%%%%.....%%%%....%%%%..",0xa,".....%%..%%..%%..%%..%%..%%..%%..%%..........%%......%%.",0xa,"..%%%%....%%%%....%%%%....%%%%...%%%%%%...%%%%....%%%%..",0xa,"........................................................",0xa,"",0x1b,"[0m", 0xa, 0xa, 0
	ppp:
		db 0xa,0xa,"",0x1b,"[0;91;49m.%%%%%%...%%%%...%%%%%%..%%......%%..%%..%%%%%...%%%%%%.",0xa,".%%......%%..%%....%%....%%......%%..%%..%%..%%..%%.....",0xa,".%%%%....%%%%%%....%%....%%......%%..%%..%%%%%...%%%%...",0xa,".%%......%%..%%....%%....%%......%%..%%..%%..%%..%%.....",0xa,".%%......%%..%%..%%%%%%..%%%%%%...%%%%...%%..%%..%%%%%%.",0xa,"........................................................",0xa,"",0x1b,"[0m", 0xa, 0xa, 0
	ggg:
		db "Checking ", 0
	rrr:
		db "Congratulations, the flag for the reverse engineering part is : ",0x1b,"[0;92;49mshellmates{", 0
	uuu:
		db "}",0x1b,"[0m",0xa,0
	www:
		db 0x1b, 0x5b, 0x30, 0x3b, 0x39, 0x34, 0x3b, 0x34, 0x39, 0x6d, 0x2e, 0x1b, 0x5b, 0x30, 0x6d, 0
	;; Now, some constants
	SYS_READ:
		dq 0
	SYS_WRITE:
		dq 1
	SYS_EXIT:
		dq 0x3c
	SYS_NANOSLEEP:
		dq 0x23
	EXIT_SUCCESS:
		dq 0
	EXIT_FAILURE:
		dq 1
	STDIN:
		dq 0
	STDOUT:
		dq 1
	STDERR:
		dq 2
section .eee progbits alloc exec write align=16
	;; our code section
	global _start
	_start:
		call fff
		db 0x89, 0x45, 0x4f, 0x5d, 0xc3
		print kkk
		call read
		db 0xe9, 0xf, 0, 0, 0
		db 0x73,0x68,0x65,0x6c,0x6c,0x6d,0x61,0x74,0x65,0x73,0x7b
		db 0xe1, 0x41, 0, 0
		call eee
		db 0xe9, 0x25, 0, 0, 0
		db 0x31,0x73,0x5f,0x37,0x68,0x31,0x73,0x5f,0x73,0x75,0x70,0x70,0x30,0x73,0x33,0x64,0x5f,0x74,0x30,0x5f,0x62,0x33,0x5f,0x74,0x68,0x33,0x5f,0x66,0x6c,0x61,0x67,0x3f,0x7d
		db 0xe1, 0x28, 0, 0
		test al, al
		jz success
		print ppp
		exit_failure
		success:
			print iii
			mov byte[aaa+32],0
			print rrr
			print aaa
			print uuu
			exit_success
	fff:
		mov rdi, [rsp]
		lea rsi, [ooo]
		push 5
		pop rcx
		boucle_fff:
			test rcx, rcx
			jz return_fff
			mov al, byte[rdi]
			mov bl, byte[rsi]
			xor al, bl
			mov byte[rdi], al
			inc rdi
			inc rsi
			dec rcx
			jmp boucle_fff
		return_fff:
			ret
	eee:
		call print_checking_status
		clear_gprs
		lea rsi, [aaa]
		lea rdi, [mmm]
		lea rdx, [nnn]
		check_boucle:
			cmp rcx, 32
			je return_check
			mov al, byte[rsi+rcx]
			mov bl, byte[rdi+rcx]
			mov r15, rbx
			mov bl, byte[rsi+r15]
			add al, bl
			mov bl, byte[rdx+rcx]
			xor al, bl
			or r8b, al
			inc rcx
			jmp check_boucle
		return_check:
			mov rax, r8
			ret
	read:
		raw_read aaa, 1024
		lea rdi, [aaa]
		mov al, 0xa
		push 1024
		pop rcx
		repne scasb
		test cx,cx
		jz read_return
		dec rdi
		mov byte[rdi],0
		read_return:
		ret
	print_checking_status:
		print ggg
		sleep 1, 0
		print www
		sleep 0, 500000000
		print www
		sleep 0, 500000000
		print www
		sleep 0, 500000000
		ret