; hexview , by fliermate (aka Mat Quasar), 2026/10
; License: CC0
;
; Dedicated to SherpaSec
;
; Version history: v0.01 - Initial release
;
; Reference:
; - https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptbinarytostringa
;
; API function calls:
;invoke GetCommandLine
;invoke CreateFileA,......
;invoke ReadFile,....
;invoke CryptBinaryToStringA,......
;invoke GetStdHandle,.......
;invoke WriteFile,........
;invoke ExitProcess,......
;

format PE console
include 'win32a.inc'

CRYPT_STRING_HEXASCIIADDR = 0x0000000b
BUFFER_SIZE=64*1024  ;Supports up to 64KB file size
STRING_SIZE=64*1024*100

section '.data' readable writeable

_err0     db 'Usage:  hexview <filename>',13,10,0
_len0     = $ - _err0
_err1     db 'Error opening file.',13,10,0
_len1     = $ - _err1
_err2     db 'Error reading file.',13,10,0
_len2     = $ - _err2
_err3     db 'Error displaying the output.',13,10,0
_len3     = $ - _err3

_dummy    dd ?
_fnlen    dd ?
_hfile    dd ?
_hout     dd ?
_len      dd ?
_count    dd STRING_SIZE
_filename rb MAX_PATH
_buffer   rb BUFFER_SIZE
_string   rb STRING_SIZE

section '.code' code readable executable

entry $
    invoke  GetStdHandle, STD_OUTPUT_HANDLE ;-11
    mov     dword [_hout],eax

    call    [GetCommandLine]
    push    eax
    cld
    mov     edi, eax
    or      ecx, -1
    xor     eax, eax
    repnz   scasb           ; Calculate total length of command line arguments
    not     ecx
    pop     eax
    push    eax
    mov     dword [_fnlen], ecx
    mov     edi, eax
    or      ecx, -1
    mov     eax, 32
    repnz   scasb           ; Find the first white space after first argument
    repz    scasb           ; Scan for extra white spacing between first argument and second argument
    not     ecx
    mov     dword [_dummy], ecx
    sub     dword [_fnlen], ecx
    cmp     dword [_fnlen], 0    ; Check if no argument is supplied
    jle     .err0
    mov     ecx, dword [_fnlen]
    pop     eax
    add     eax, dword [_dummy]
    dec     eax
    xor     ebx, ebx
    cmp     byte [eax], '"'      ; Check if path is enclosed in quotes
    setz    bl
    sub     ecx, ebx
    sub     ecx, ebx
    mov     esi, eax
    add     esi, ebx
    lea     edi, [_filename]
    rep     movsb

    invoke  CreateFile, _filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    mov     dword [_hfile], eax
    cmp     eax, INVALID_HANDLE_VALUE
    je      .err1

    invoke  ReadFile, dword [_hfile], _buffer, BUFFER_SIZE, _len, 0
    test    eax, eax
    jz      .err2
    mov     ecx, dword [_len]
    test    ecx, ecx
    jz      .close

    invoke  CryptBinaryToStringA, _buffer, dword [_len], CRYPT_STRING_HEXASCIIADDR, _string, _count
    or      eax,eax
    jz      .err3
    inc     dword [_count]
    invoke  WriteFile, dword [_hout], _string, dword [_count], _dummy, 0 ;Output can be redirected to text file using ">" or ">>" in command line

.close:
    invoke  CloseHandle, [_hfile]
    jmp     .done

.err0:
    lea     edx, [_err0]
    mov     ecx, _len0
    jmp     .error
.err1:
    lea     edx, [_err1]
    mov     ecx, _len1
    jmp     .error
.err2:
    lea     edx, [_err2]
    mov     ecx, _len2
    jmp     .error
.err3:
    lea     edx, [_err3]
    mov     ecx, _len3
.error:
    invoke  WriteConsole, dword [_hout], edx, ecx, _dummy, 0

.done:
    invoke  ExitProcess,0

section '.idata' import readable writable

  library kernel32, 'KERNEL32.DLL' ,\
          crypt32, 'CRYPT32.DLL'

  import kernel32,\
         GetStdHandle, 'GetStdHandle', \
         WriteConsole, 'WriteConsoleA', \
         CreateFile, 'CreateFileA', \
         ReadFile, 'ReadFile', \
         WriteFile, 'WriteFile', \
         CloseHandle, 'CloseHandle', \
         GetCommandLine, 'GetCommandLineA', \
         ExitProcess,'ExitProcess'

  import crypt32,\
         CryptBinaryToStringA,'CryptBinaryToStringA'