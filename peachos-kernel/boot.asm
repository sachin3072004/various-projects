; 0x55AA is the bootloader segment signature.
;bootloader looks for 0x55AA. But because of intel is little endian thats wy we have kept 0xAA55.
ORG 0x0
BITS 16

start:
	cli;
	mov ax, 0x7c0
	mov ds, ax
	mov es, ax
	mov ax, 0x00
	mov ss, ax
	mov sp, 0x7C00
	sti;
	
	mov ah, 2
	mov al, 1
	mov ch, 0
	mov cl, 2
	mov dh, 0
	mov bx, buffer
	int 0x13
	jc error
	
	mov si,buffer
	call print
	jmp $
error:
	mov si, error_message
	call print
	jmp $
print:
	mov bx, 0
.loop:
	lodsb
	cmp al, 0
	je .done
	call print_char
	jmp .loop
.done:
	ret
print_char:
	mov ah, 0eh 
	int 0x10
	ret

error_message: db 'Failed to load sector', 0
times 510-($-$$) db 0
dw 0xAA55

buffer:
