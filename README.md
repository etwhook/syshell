
# 🉐🔱 SysHell

Evasion Via **Direct Syscalls** with **Hell's** Gate Written In **Nim**. 


## 🏯 Examples
```
$ ./syshell.exe -i functions.txt -o funcs.asm
```
#### Output
```
.code

NtAllocateVirtualMemory PROC
mov r10, rcx
mov eax, 24 ; (SSN)
syscall
ret
NtAllocateVirtualMemory ENDP

NtClose PROC
mov r10, rcx
mov eax, 15 ; (SSN)
syscall
ret
NtClose ENDP

NtOpenProcess PROC
mov r10, rcx
mov eax, 38 ; (SSN)
syscall
ret
NtOpenProcess ENDP

end
```
You Can Also **Generate** **Inline Assembly** For Nim Using the ``--nim`` Flag, This Tool Does **NOT** Support Getting Functions Arguments / Parameters However.


