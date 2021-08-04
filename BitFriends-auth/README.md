# BitFriends - auth (difficulty: 3.0)

## Problem

We are given a single ELF (`auth`) with all protections enabled.

Running it asks us for a username, which it then prints back to us. It then asks for a password:

![default_behavior](https://user-images.githubusercontent.com/86139991/128198660-a76459e0-2d23-4ef9-93f6-27e1914f4884.PNG)

Presumably, the goal is to find a password which doesn't get us kicked out the door. Since we get our input printed back at us, one potential vector of attack to look at is a
`printf` read primitive, followed by a function pointer overwrite.

## Reversing

This is a fairly simple reversing job. Importing into Ghidra shows that the main program consists of four named functions: `main`, `auth`, `authenticated`, and `normal`:.

![functions](https://user-images.githubusercontent.com/86139991/128199173-755dd240-6492-4c54-97e0-a4e05b97acfe.PNG)

Examining `main` shows that it reads in our username (which can be up to `0x10` bytes) and `printf`s it back to us, then calls `auth`, which presumably reads the password. This
gives us our first vulnerability: the username is `printf`'d back at us with no formatting. Since we can only input `0x10` bytes, there is unlikely to be a write primitive here,
but we can certainly read from anywhere on the stack and bypass ASLR.

![main](https://user-images.githubusercontent.com/86139991/128199979-c6680539-06d9-4011-a57b-77e10dd43abe.PNG)

The `auth` function is where the fun begins. This function allocates `0x40` bytes for our password on the stack, then very conspicuously sets the address `password + 0x68` to
the address of `normal()`. A full `1000` bytes of password are then read in, and the function at `password + 0x68` is executed. This is, of course, an overflow. Since no later
chunks are allocated, we cannot corrupt the heap, but we can very easily overwrite the function pointer at `password + 0x68`.

![auth](https://user-images.githubusercontent.com/86139991/128200381-5e6b482b-aaba-4757-b208-6a3fe8a3e543.PNG)

Quickly examining the `normal` and `authenticated` functions shows that `normal` prints "Wrong password", while `authenticated` prints "nice job".

## Exploiting

Given all this, our plan of attack is clear:

- Use the `printf` vulnerability to uncover the address of a function in the binary
- Calculate the offset from this function to `authenticated`
- Overwrite the pointer to `normal` at `password + 0x68` with the address of `authenticated`
- Profit

### Getting a function address

The first order of business is to leak a function address using `printf`. Our first idea was to submit `username = "%p%p%p%p%p%p%p"`, in an attempt to leak the return address:

![first_attempt](https://user-images.githubusercontent.com/86139991/128201456-5609f66b-c78a-4712-a772-578fecdc0763.PNG)

Unfortunately, inspecting these addresses in `gdb` reveals that none are function addresss. The first two seem to be heap segments used by `printf`, while the third is the
address of `argv`. Note that this does leak the address of the stack. If DEP was disabled, we could have entered a username of "%p%p%p%p%p%p" followed by a jump to a register
which points to data we control, then overwritten the function address at `password + 0x68` with the calculated address of our username on the stack. However, since DEP is
enabled, this resulted in a segfault upon returning to the stack.

Since none of these addresses were useful, we decided to enumerate values on the stack using the following loop in `pwntools`:

```py
import pwn

for i in range(1, 100):
  io = pwn.process([BIN_PATH], level="error")
  io.sendline("%{}$p".format(i))
  print("{}: {}".format(i, io.recvline()))
  io.close()
```

Doing this revealed relevant information at the 8th and 9th values:

![leaked_values](https://user-images.githubusercontent.com/86139991/128203308-b3d523cc-f017-4ae7-bb92-0fdf7236c789.PNG)

The 9th address is very similar to the addresses of functions we saw in `gdb`. If we assume that this is the return function, then the 8th value might be a stack canary.

Let's print the 9th address specifically and attach GDB to confirm that this is, indeed, a function address:

```py
import pwn

io = pwn.process([BIN_PATH], level="error")
io.sendline("%9$p")
print(str(io.recvline))
pwn.gdb.attach(io)
io.close()
```

This prints the address `0x55bbfac8090`, which GDB confirms is the address of `_start` in the binary.

![_start](https://user-images.githubusercontent.com/86139991/128204413-bc54c0c7-69ee-490c-be7f-c14709a20b45.PNG)

Using GDB to find the address of `authenticated` reveals that it is at an offset of `+0x10c` to this address:

![authenticated](https://user-images.githubusercontent.com/86139991/128204650-a5203fa8-302e-4c2f-8cc1-8f85e4737b79.PNG)

### Overwriting the pointer

By revealing and calculating the address to overwrite our function pointer with, we have done the hard part. Now all that is left is to overwrite the pointer at `password + 0x68`
with this address.

Once more, using `pwntools`:

```py
import pwn

io = pwn.process([BIN_PATH], level="error")
io.sendline("%9$p")
response = io.recvline()

start_addr = int(str(response).split("x")[1].split(",")[0], 16) # extract the address of _start from the response
authenticated_addr = start_addr + int("10c", 16)
io.sendline(b"a"*int("68", 16) + pwn.util.packing.p64(authenticated_addr))
print(str(io.recvline()))
```

This prints "Right password".

## Solution
The full solution can be found in this folder as `main.py`.
