#  echo “hello_world” > /dev/faulty
Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
Mem abort info:
  ESR = 0x96000045
  EC = 0x25: DABT (current EL), IL = 32 bits
  SET = 0, FnV = 0
  EA = 0, S1PTW = 0
  FSC = 0x05: level 1 translation fault
Data abort info:
  ISV = 0, ISS = 0x00000045
  CM = 0, WnR = 1
user pgtable: 4k pages, 39-bit VAs, pgdp=0000000042115000
[0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
Internal error: Oops: 96000045 [#1] SMP
Modules linked in: hello(O) faulty(O) scull(O)
CPU: 0 PID: 158 Comm: sh Tainted: G           O      5.15.18 #1
Hardware name: linux,dummy-virt (DT)
pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
pc : faulty_write+0x14/0x20 [faulty]
lr : vfs_write+0xa8/0x2b0
sp : ffffffc008d23d80
x29: ffffffc008d23d80 x28: ffffff80020c8000 x27: 0000000000000000
x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
x23: 0000000040001000 x22: 0000000000000012 x21: 00000055939d2a70
x20: 00000055939d2a70 x19: ffffff8002087c00 x18: 0000000000000000
x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
x5 : 0000000000000001 x4 : ffffffc0006f7000 x3 : ffffffc008d23df0
x2 : 0000000000000012 x1 : 0000000000000000 x0 : 0000000000000000
Call trace:
 faulty_write+0x14/0x20 [faulty]
 ksys_write+0x68/0x100
 __arm64_sys_write+0x20/0x30
 invoke_syscall+0x54/0x130
 el0_svc_common.constprop.0+0x44/0xf0
 do_el0_svc+0x40/0xa0
 el0_svc+0x20/0x60
 el0t_64_sync_handler+0xe8/0xf0
 el0t_64_sync+0x1a0/0x1a4
Code: d2800001 d2800000 d503233f d50323bf (b900003f) 
---[ end trace 48d763bcbb43a23b ]---


Analysis : 

#Reference : The Kernel debugging video helped me to understanding this. 

1) The first line "Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000" says that the error occured because of the kernel attempting to dereference a NULL pointer.

2) The next line will give mem abort info and the data abort info of the register values during the time of crash.

3) "CPU: 0 PID: 158 Comm: sh Tainted: G           O      5.15.18 #1" --- This line shows the CPU on which the fault occured. PID 158 is the process ID causing the issue. "Tainted: G" flag indicates that the kernel was tainted by loading a proprietary module.

4) "pc : faulty_write+0x14/0x20 [faulty]" --- This says the program counter at the time of crash. The crash happened when executing the function faulty_write. +0x14" indicates that the crash occurred 20 bytes into the "faulty_write" function. This means that the specific instruction or operation that caused the crash was located 20 bytes from the beginning of the function. "/0x20" tells us that the entire "faulty_write" function has a length of 32 bytes.

5) "lr : vfs_write+0xa8/0x2b0" --- The link register here is used to save the return address between function calls

6) "sp : ffffffc008d23d80" --- The address of the stack pointer 

7) The next lines after the stack pointer is the core dump of the CPU registers. 

8) The call stack displayed here reveals the sequence of function calls that led to the crash. It illustrates the hierarchical order of function calls that ultimately resulted in the program encountering an issue or crash.




