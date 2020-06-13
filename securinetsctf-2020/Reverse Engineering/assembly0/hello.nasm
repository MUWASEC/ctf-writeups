	section .data ;Data segment Section data
msg: db "Hello world!", 0x0a  ;The string and newline char

	global		_start  ; Default entry point for ELF linking
	section .text 		; Text segment

;SYSCALL: write(1,msg,14) appel system 
_start:		mov eax, 0	 ;Put 0 into eax.
			mov ebx, msg ;Put the address of the string into ebx.
			xor byte [ebx+eax], 0x06 ;xor [ebx+eax] with 0x06
			add eax, 1   ;increment eax by 1
			xor byte [ebx+eax], 0x04
			add eax, 1
			xor byte [ebx+eax], 0x1f
			add eax, 1
			xor byte [ebx+eax], 0x01
			add eax, 1
			xor byte [ebx+eax], 0x30
			add eax, 1
			xor byte [ebx+eax], 0x52
			add eax, 1
			xor byte [ebx+eax], 0x02
			add eax, 1
			xor byte [ebx+eax], 0x03
			add eax, 1
			xor byte [ebx+eax], 0x17
			add eax, 1
			xor byte [ebx+eax], 0x1f
			add eax, 1
			xor byte [ebx+eax], 0x45
			add eax, 1
			xor byte [ebx+eax], 0x00
			mov ecx, ebx ;Put the address of the string into ecx.
			xor eax, eax
			mov eax, 4   ;Put 4 into eax, since write is syscall #4.
			mov ebx, 1   ;Put 1 into ebx, since stdout is 1.
			mov edx ,14   ;Put 14 into edx, since our string is 14 bytes.
			int 0x80     ;Call the kernel to make the system call happen.

;SYSCALL: exit(0)

			mov eax, 1	;Put 1 into eax, since exit is syscall #1.
			mov ebx, 0
			int 0x80
