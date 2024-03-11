import winim, ptr_math, cligen, strutils, strformat
{.passC:"-masm=intel".}
proc FetchPEB*(): PPEB {.asmNoStackFrame.} =
    asm """
    mov rax, gs:[0x60]
    ret
    """

let peb: PPEB = FetchPEB()
let ldr: PPEB_LDR_DATA = cast[PPEB_LDR_DATA](peb.Ldr)
var pDte: PLDR_DATA_TABLE_ENTRY = cast[PLDR_DATA_TABLE_ENTRY](ldr.InMemoryOrderModuleList.Flink)

proc CustomLoadLibraryA*(libName: string): HMODULE =
    while pDte.FullDllName.Length != 0:
        let name = $(pDte.FullDllName.Buffer)
        let handle = cast[HMODULE](pDte.Reserved2[0])
        if lstrcmpiA(name, libName) == 0:
            return handle
        pDte = (cast[ptr PLDR_DATA_TABLE_ENTRY](pDte))[]



proc getAsmSyscallCode(fn: string, ssn: int , nimf: bool = false): string =
    if nimf == false:
        result = fmt"""
{fn} PROC
mov r10, rcx
mov eax, {ssn}
syscall
ret
{fn} ENDP
"""
    else:
        var p = "\"\"\""
        result = fmt"""
proc {fn}*() {{.asmStackFrame.}} =
    asm {p}
    mov r10, rcx
    mov eax, {ssn}
    syscall
    ret
    {p}
"""

let base = CustomLoadLibraryA("ntdll.dll")
let pe = cast[DWORD_PTR](base)
let dosHeader = cast[PIMAGE_DOS_HEADER](pe)
let ntHeader = cast[PIMAGE_NT_HEADERS](pe + dosHeader.elfanew)
let optHeader = ntHeader.OptionalHeader
var eat: PIMAGE_DATA_DIRECTORY = cast[PIMAGE_DATA_DIRECTORY](&(optHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]))
var eatDir: PIMAGE_EXPORT_DIRECTORY = cast[PIMAGE_EXPORT_DIRECTORY](pe + eat.VirtualAddress)
var names: PDWORD = cast[PDWORD](pe + eatDir.AddressOfNames)
var functions: PDWORD = cast[PDWORD](pe + eatDir.AddressOfFunctions)
var ordinals: PWORD = cast[PWORD](pe + eatDir.AddressOfNameOrdinals)
var numNames: DWORD = eatDir.NumberOfNames

proc dumpSSNs*(input, output: string, nim: bool = false) =
    var found: int = 0
    let inputFunctions = open(input, fmRead).readAll().splitLines()
    let outputFile = open(output, fmAppend)
    if not nim:
        outputFile.write(".code\n\n")
    block outer:
        for i in 0..numNames:
            var funcName = cast[LPCSTR](pe + names[i])

            if $funcName in inputFunctions:
                var ordinal = cast[DWORD](ordinals[i])
                var rvaToFunc = cast[DWORD](functions[ordinal])
                var address = cast[PBYTE](pe + rvaToFunc)
                var cw = 0
                block inner:
                    while true:
                        if ((address + cw)[]) == 0x0f and ((address + cw + 1)[]) == 0x05:
                            echo(fmt"[-] Failed To Fetch SSN For {$funcName}")
                            break inner
                        if ((address + cw)[]) == 0xc3:
                            break inner

                        if ((address + cw)[] == 0x4c) and ((address + 1 + cw)[] == 0x8b) and ((address + 2 + cw)[] == 0xd1) and ((address + 3 + cw)[] == 0xb8) and ((address + 6 + cw)[] == 0x00) and ((address + 7 + cw)[] == 0x00):
                            let h = (address + 5 + cw)[]
                            let l = (address + 4 + cw)[]
                            let wSyscall = (h shl 8) or l
                            let code = getAsmSyscallCode($funcName, wSyscall.int, nim)
                            #echo code
                            outputFile.write(code & "\n")
                            found += 1
                            break inner
                    inc(cw)
    if not nim:
        outputFile.write("end\n")
    outputFile.close()
    echo(fmt"Found {found} Syscalls' SSNs.")


when isMainModule:
    dispatch dumpSSNs