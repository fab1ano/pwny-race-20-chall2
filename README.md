chall2
======

This binary was the second challenge in our internal pwny race.

## Player Info
The players only get the binary itself.

## Challenge Idea
The binary accepts TCP connections on a ports and forks for handling each connection.
The stack cookie is then updated to be a pseudo random value depending on the time, such that the attacker can calculate the exact value.
Since the binary is PIE, the attacker needs to brute force the binary address (Due to fork the address space is the same for every execution).
From there a libc address leak (rop chain) and a one shot (`one_gadget`) is possible.

## Exploit Approach
* calculate the cookie
* brute-force the binary address
* leak libc address
* jump to one_gadget
