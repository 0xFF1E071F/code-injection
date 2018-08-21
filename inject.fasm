    format PE GUI 6.0
    entry start

;  Injecting code into a running process
; ------------------------------------------------------------------------------------
;                    _______          ____  ________          ________  ____
;            ___  ___\   _  \ _______/_   |/   __   \___  ___/   __   \/_   |
;            \  \/  //  /_\  \\_  __ \|   |\____    /\  \/  /\____    / |   |
;             >    < \  \_/   \|  | \/|   |   /    /  >    <    /    /  |   |
;            /__/\_ \ \_____  /|__|   |___|  /____/  /__/\_ \  /____/   |___|
;                    \/       \/                             \/
; ------------------------------------------------------------------------------------

    include '\fasm\include\win32ax.inc'

    TH32CS_SNAPPROCESS      =   2
    ACCESS_FLAGS            =   0x1f0fff
    SE_PRIVILEGE_ENABLED    =   2
    TOKEN_ADJUST_PRIVILEGES =   0x20
    THREAD_ALL_ACCESS       =   0x1f03ff
    KERNEL32                =   0x29cdd463

section '.text' executable writeable readable

    tid     dd  ?
    procEnt dd  0x128
            rb  292
    target  db  'notepad', 0
    target.size = $-target
    align 16
    context dd  0x10007
            rb  712

InjectProc:
    call @f
    text        db  'This MessageBox has been created by code injection !', 0
    text.size   =   $-text
    title       db  '[ x0r19x91 ] ~ Code Injection Demo', 0
    title.size  =   $-title
    aLoadLib    db  'LoadLibraryA', 0
    aLoadLib.size = $-aLoadLib
    aFuncEx     db  'GetProcAddress', 0
    aFuncEx.size = $-aFuncEx
    aCount      dd  0
    fnLoadLib   dd  0
    fnProc      dd  0
    dExport     dd  0
    LOAD_LIB    =   text.size+title.size
    PROC_ADDR   =   LOAD_LIB+aLoadLib.size
    PIPE        =   PROC_ADDR+aFuncEx.size+16
@@:
    pop ebp
    mov eax, [fs:0x30]
    mov eax, [eax+12]
    mov ebx, [eax+12]

.search:
    movzx ecx, word [ebx+0x2c]
    mov esi, [ebx+0x30]
    mov ecx, 0x811c9dc5

.hash:
    movzx edx, word [esi]
    or dx, dx
    jz .L2
    cmp dl, 'a'
    jb .L1
    sub dl, 32
.L1:
    xor ecx, edx
    imul ecx, 0x1000193
    add esi, 2
    jmp .hash
.L2:
    cmp ecx, KERNEL32
    jz .found_kernel32
    mov ebx, [ebx]
    jmp .search

.found_kernel32:
    mov eax, [ebx+0x18]
    mov ebx, [eax+0x3c]
    mov ebx, [eax+ebx+24+96]
    add ebx, eax
    mov esi, [ebx+32]   ; Names
    add esi, eax
    mov edi, [ebx+36]   ; Addresses
    add edi, eax
    mov ecx, [ebx+24]
    mov [ebp+text.size+title.size+aLoadLib.size+aFuncEx.size], ecx
    mov [ebp+text.size+title.size+aLoadLib.size+aFuncEx.size+12], ebx
    mov ebx, eax
    xor eax, eax

.search_loop:
    mov edx, esi
    mov esi, [esi]
    add esi, ebx
    push edi
    lea edi, [ebp+text.size+title.size]
    mov ecx, aLoadLib.size
    repz cmpsb
    pop edi
    jnz .procaddr
    push word [edi]
    pop word [ebp+LOAD_LIB]
    or al, 1
    jmp .next

.procaddr:
    mov esi, [edx]
    add esi, ebx
    push edi
    lea edi, [ebp+text.size+title.size+aLoadLib.size]
    mov ecx, aFuncEx.size
    repz cmpsb
    pop edi
    jnz .next
    push word [edi]
    pop word [ebp+PROC_ADDR]
    or al, 2

.next:
    cmp al, 3
    jz .prepare
    add edi, 2
    mov esi, edx
    add esi, 4
    dec dword [ebp+text.size+title.size+aLoadLib.size+aFuncEx.size]
    jnz .search_loop

.prepare:
    mov ecx, [ebp+text.size+title.size+aLoadLib.size+aFuncEx.size+12]
    mov ecx, [ecx+28]
    movzx eax, word [ebp+LOAD_LIB]
    add ecx, ebx
    mov ecx, [ecx+eax*4]
    add ecx, ebx
    mov [ebp+LOAD_LIB], ecx
    mov ecx, [ebp+text.size+title.size+aLoadLib.size+aFuncEx.size+12]
    mov ecx, [ecx+28]
    movzx eax, word [ebp+PROC_ADDR]
    add ecx, ebx
    mov ecx, [ecx+eax*4]
    add ecx, ebx
    mov [ebp+PROC_ADDR], ecx
    
    call @f
    aUser       db  'user32.dll', 0
    aUser.size  =   $-aUser
    aMsgBox     db  'MessageBoxA', 0
    aMsgBox.size =  $-aMsgBox
    aFind       db  'FindWindowA', 0

@@:
    mov ebx, [esp]
    call dword [ebp+LOAD_LIB]
    mov esi, eax
    lea edx, [ebx+aUser.size+aMsgBox.size]
    push edx
    push eax
    call dword [ebp+PROC_ADDR]
    push 0
    call @f
    szClass     db  'Notepad', 0
@@:
    call eax
    mov edi, eax
    lea edx, [ebx+aUser.size]
    push edx
    push esi
    call dword [ebp+PROC_ADDR]
    push 0x40
    lea ecx, [ebp+text.size]
    push ecx
    push ebp
    push edi
    call eax

.local_loop:
    db 0xeb, 0xfe


InjectProc.size = $-InjectProc

start:
    invoke CreateToolhelp32Snapshot, TH32CS_SNAPPROCESS, 0
    mov ebp, eax
    invoke Process32First, ebp, procEnt

.process_search:
    lea edi, [procEnt+36]
    mov esi, target
    mov ecx, target.size
    repz cmpsb
    or cl, cl
    jz .inject
    invoke Process32Next, ebp, procEnt
    or al, al
    jnz .process_search
    invoke CloseHandle, ebp
    jmp .exit

.inject:
    invoke CloseHandle, ebp
    lea eax, [procEnt]
    mov eax, [eax+8]
    invoke OpenProcess, ACCESS_FLAGS, FALSE, eax
    or eax, eax
    jz .exit
    mov ebp, eax
    invoke VirtualAllocEx, ebp, 0, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE
    or eax, eax
    jz .exit
    mov ebx, eax
    invoke WriteProcessMemory, ebp, eax, InjectProc, InjectProc.size, 0
    invoke CreateRemoteThreadEx, ebp, 0, 0, ebx, 0, CREATE_SUSPENDED, 0, tid
    mov edi, eax
    mov esi, context
    invoke GetThreadContext, edi, esi
    mov [esi+184], ebx
    invoke SetThreadContext, edi, esi
    invoke ResumeThread, edi

.exit:
    invoke ExitProcess, 0


section '.idata' import readable writeable

    library kernel32, 'kernel32.dll'

    import kernel32,\
        CreateToolhelp32Snapshot, 'CreateToolhelp32Snapshot',\
        Process32First, 'Process32First',\
        Process32Next, 'Process32Next',\
        ExitProcess, 'ExitProcess',\
        VirtualAllocEx, 'VirtualAllocEx',\
        OpenProcess, 'OpenProcess',\
        CloseHandle, 'CloseHandle',\
        CreateRemoteThreadEx, 'CreateRemoteThreadEx',\
        GetThreadContext, 'GetThreadContext',\
        SetThreadContext, 'SetThreadContext',\
        ResumeThread, 'ResumeThread',\
        WriteProcessMemory, 'WriteProcessMemory',\
        CreateNamedPipe, 'CreateNamedPipeA',\
        WriteFile, 'WriteFile'