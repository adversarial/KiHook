;;
;; KiHook - ntdll system call hooking module
;;
;; fasm assembler
;;
;; Copyright (c) 2014 adversarial

format PE GUI 6.0 DLL NX
entry DllMain

include 'win32a.inc'

;
; Control flow:
;
; Process->
;   kernel32!Xxx->
;     ntdll!Xxx->
;       (hooked)ntdll!KiFastSystemCall->
; KiHook!HKiFastSystemCallback->
;   Saves return address and replaces with KiHook!HKiFastSystemCallbackRet
;   Hooks added via KiHook!HKiInstallCallback->
;     KiHook->KiFastSystemCallStub->
; Enters r0->
;   Returns to KiFastSystemCallbackRet->
; KiHook!HKiFastSystemCallbackRet->
;   Restores original return address
;   Hooks added via KiHook!HKiInstallCallbackRet->
; Process
;

; Besides causing ntdll to become unshared and have new pages, each call is
; also routed through these functions. Significant performance hits may occur
; on longer installed callback lists
;
; Only use this module on short lists, instead use an fs:$0c hook or other

;
;  Callbacks:
;
;      typedef int (*HKICALLBACK)(uint32_t* args);
;
;  args is a pointer to an array of args pushed in reverse order, a va_list
;  can be constructed if number of args is known by:
;
;      va_list arglist = args - num_args;
;
;  May return either
       CONTINUE = 1
       ABORT = 0
       EXECUTE_NORMAL = -1
;
;  CONTINUE means that the operation was successful and should continue as
;    normal
;  ABORT means that the operation was unsuccessful and the syscall should
;    NOT be made. This will return control to the original process, ignoring
;    any post-handlers.
;  EXECUTE_NORMAL means that other handlers of the same catergory should be
;    skipped (if returned by a pre handler, post handlers will still be
;    executed).
;
;  Internal list:
;
;  struct {
;         void*         Flink;
;         uint32_t      Ordinal;
;         HKICALLBACK   Handler;
;  } *KiPreCallbackList, *KiPostCallbackList;

;; = Code =====================================================
section '.text' code readable executable
;
; Must be aligned to $c3 because of ret instruction
;
; KiFastSystemCall:
; { $eb $xx, $xx, $xx, $c3 }
; { jmp HKiFastSystemCallback , ret }
;
; Fasm does not compile: (cannot use $ because relocation)
; db ((($ / c3) + 1) * c3) dup(0)
;
align $100

;
; Syscall stub (to avoid setting w access in our section)
;
KiFastSystemCallStub:
        mov edx, esp
        sysenter
        ret

db ($c3-($-KiFastSystemCallStub)) dup(0)

;
; Recieves control from ntdll!KiFastSystemCall, handles giving control to each
; callback and setting return address hook
;
; Must be aligned to $c3
;
HKiFastSystemCallback:

        push eax ecx edx

        ; TODO: Iterate through callback list

        invoke TlsGetValue,[TlsIndex]   ; retrieves a uint32_t* local to thread
        mov edx, [esp]                  ; return addr of ntdll!KiFastSystemcall
        mov [eax], edx                  ; save return addr *(uint32_t*)TlsData

        mov dword [esp], HKiFastSystemCallbackRet ; Hook return from
                                                  ; ntdll!KiFastSystemcallRet

        pop edx ecx eax

        jmp KiFastSystemCallStub        ; our stored function

;
; Revieces control from ntdll!KiFastSystemCallRet, handles giving control to
; each post callback and resetting return address, then returning to process
;
HKiFastSystemCallbackRet:

        push 0 eax ecx edx

        invoke TlsGetValue,[TlsIndex]   ; retrive uint32_t* local to thread
        mov ecx, [eax]                  ; original return addr
        mov [esp+4*3], ecx              ; our push 0 will be ret addr
        mov dword [eax], 0              ; set *TlsData to NULL

        ; TODO: Iterate through callback list

        pop edx ecx eax                 ; restore used registers
        ret                             ; return to original addr


;
; Adds a callback to the pre callback list.
;
; HKiCALLBACK* HKiAddCallback(int Ordinal, )
HKiFastSystemCallAddCallback:

;
; Removes a callback from the pre callback list
;
HKiFastSystemCallRemoveCallback:


;
; Acquires a lock to the KiFastSytemCall mutex
; Returns (bool)FLAGS.CF true if lock can be acquired, false if already locked
;
HKiFastSystemCallAcquireLock:
  ; Mutex is set to ~0 if locked
        xor edx, edx
        not edx
  ; check if lock is clear
        mov eax, [KiFastSystemCallLock]
        test eax, eax
        jnz .AlreadyLocked

  ; grab lock
        lock cmpxchg [KiFastSystemCallLock], edx

  ; make sure we grabbed it
        test eax, eax
        jnz .AlreadyLocked
        stc
        ret

  .AlreadyLocked:
        clc
        ret
;
; Releases a lock to the KiFastSytemCall mutex
; Returns (bool)FLAGS.CF true if lock was already acquired and released, false
; if lock was not already acquired
;
HKiFastSystemCallReleaseLock:
  ; Mutex is set to 0 if unlocked
        xor edx, edx
  ; Make sure lock is actually set
        mov eax, [KiFastSystemCallLock]
        test eax, eax
        jz .NotAlreadyLocked

  ; Release lock
        lock cmpxchg [KiFastSystemCallLock], edx

  ; Ensure we released it before someone else
        test eax, eax
        jnz .NotAlreadyLocked
        stc
        ret

  .NotAlreadyLocked:
        clc
        ret

;
; Initializes the hook and sets up the callback chain
;
; void* HKiFastSystemCallHookCtor(void* (*pKiFastSystemCall)())
HKiFastSystemCallHookCtor:

        stdcall HKiFastSystemCallAcquireLock
        jnc .LockFailed

        mov edi, [esp+4*1]      ; &ntdll!KiFastSystemCall

        sub esp, $4             ; DWORD OldProtection
        invoke VirtualProtect,edi,$8,PAGE_EXECUTE_READWRITE,esp

        mov eax, edi            ; &ntdll!KiFastSystemCall

        sub esp, $8             ; unsigned char InjectBuffer[8]

        ; buffer outline at [esp]:
        ; { jmp, HKiFastSystemCallback, .., .., ..}

        mov byte [esp], $e9     ; JMP opcode
        ; unaligned writes dgaf
        mov dword [esp+1], HKiFastSystemCallback
        ; last 3 bytes (saved from old func)
        lea esi, [eax+5]
        lea edi, [esp+5]
        mov ecx, $3             ; 8 - sizeof.opcode(jmp imm32)
        rep movsb

        mov edi, eax            ; &ntdll!KiFastSystemCall

        ; ecx:ebx is value to write
        mov ecx, [esp]
        mov ebx, [esp+4]

  .AtomicWriteHook:
          ; first set edx:eax to qword [edi] on mismatch
          lock cmpxchg8b [edi]
          ; then write ecx:ebx to qword [edi] when edx:eax matches qword [edi]
          lock cmpxchg8b [edi]
          ; Flags.ZF should equal 1 on success, 0 on failure
          ;jnz .AtomicWriteHook
          ; However, we'll just let it slide as it's unconditional swapping

        add esp, $8             ; free InjectBuffer

        invoke VirtualProtect,edi,$8,[esp],esp
        add esp, $4             ; free OldProtection

        mov eax, 1
        ret 4

  .LockFailed:
        xor eax, eax
        ret 4
;
; Releases lock on KiFastSystemCallLock and unhooks KiFastSystemCall
;
HKiFastSystemCallHookDtor:

        ; TODO: unhook KiFastSystemCall

        stdcall HKiFastSystemCallReleaseLock
        jnc .LockReleaseFailed
        mov eax, 1
        ret

  .LockReleaseFailed:
        xor eax, eax
        ret

;
; Allocates TLS data, not much else to do here until Ctor is called
;
DllMain:
        mov eax, [esp+4*1]      ; fdwReason
  ;; DLL_PROCESS_ATTACH
        cmp eax, DLL_PROCESS_ATTACH
        jne @f

        invoke TlsAlloc
        cmp eax, TLS_OUT_OF_INDEXES
        je .failret

        mov [TlsIndex], eax

        jmp .ret
  ;; DLL_THREAD_ATTACH
  @@:   cmp eax, DLL_THREAD_ATTACH
        jne @f

        invoke LocalAlloc,LPTR,4
        invoke TlsSetValue,[TlsIndex],eax

        jmp .ret
  ;; DLL_THREAD_DETACH
  @@:   cmp eax, DLL_THREAD_DETACH
        jne @f

        invoke TlsGetValue,[TlsIndex]
        invoke LocalFree,eax
        jmp .ret
  ;; DLL_PROCESS_DETACH
  @@:   cmp eax, DLL_PROCESS_DETACH
        jne .ret

        invoke TlsFree, [TlsIndex]

  .ret:
        mov eax, 1
        ret 4*3

  .failret:
        mov eax, 0
        ret 4*3


;; = Imports ==================================================
data import
     library kernel32,'kernel32'

     import kernel32,\
            \; dgaf I don't want to bother with an extra call to GetDefaultHeap
            LocalAlloc,'LocalAlloc',\
            LocalFree,'LocalFree',\
            \;
            TlsAlloc,'TlsAlloc',\
            TlsGetValue,'TlsGetValue',\
            TlsSetValue,'TlsSetValue',\
            TlsFree,'TlsFree',\
            VirtualProtect,'VirtualProtect'
end data

;; = Exports ==================================================
data export
     export 'KiHook.dll',\
     HKiFastSystemCallHookCtor,'HKiFastSystemCallHookCtor@4'
end data

;; = Reloc ====================================================
data fixups
end data

;; = Data =====================================================
section '.data' data readable writeable
KiFastSystemCallLock dd ?       ; mutex that tells if hook is already overlaid
KiPreCallbackList    dd ?       ; ptr to HKICALLBACKLIST that is parsed before
                                ; KiSystemCall
KiPostCallbackList   dd ?       ; ptr to HKICALLBACKLIST that is parsed after
                                ; KiSystemCallRet

; the dll will just manually implement calls to TLS so my loader doesnt
; need to register it for callbacks

;; = TLS header ===============================================
TLS_OUT_OF_INDEXES = -1
TlsIndex dd ?

;tls = 9
;
; Windows documentation is complete crap for TLS, and I couldn't find any
; examples for using TLS data (like what RawData***Va really meant). Notes here:
;
; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
; struct IMAGE_TLS_HEADER {
;     .RawDataStartVA     dd 0    ; Points to beginning of initialized variables
                                  ; The structure will be copied to the TLSData
                                  ; block
;     .RawDataEndVA       dd 0    ; End of said statically-assigned variables
                                  ; block
;     .AddressOfIndex     dd ReturnTlsIndex ; DWORD* that holds the TLS slot,
                                            ; will be set by loader
;     .AddressOfCallbacks dd 0    ; Pointer to list of void (*callback())
;     .SizeOfZeroFill     dd 0    ; Size of uninitalized variables. Appended to
                                  ; initialized data block so that
; cbTlsDataBlock = RawDataStart - RawDataEnd + SizeOfZeroFill
;     Reserved           dd 0
; =-=-=-=-=-=-=-=-=-=-=-=-=-=-=--=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
;data 9
;     RawDataStartVA     dd 0
;     RawDataEndVA       dd 0
;     AddressOfIndex     dd TlsIndex
;     AddressOfCallbacks dd 0
;     SizeOfZeroFill     dd 4    ; We only need one void*
;     Reserved           dd 0

; FASM appears to crash if the TLS section header is outside a w
; section... preemptively saving us from windows crashing it, but no error
; fasmw just crashes
;end data

