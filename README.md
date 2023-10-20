**PyU8disas** is an nX-U8/100 core disassembler written in Python. It tries to mimic the original, intended assembly syntax of the U8 architecture. (except for the addresses and instruction opcodes)

# Usage
```
options:
  -h, --help            show this help message and exit
  -n, --ignore-interrupts
                        treat the interrupt vector area as normal code
  -a, --hide-addresses  hide addresses and operands in disassembly
  -u, --no-unused       don't add the _UNUSED suffix for unused functions
  -o output, --output output
                        name of output file (default = 'disas.asm')
  -d, --debug           enable debug logs
```

# Other U8 disassemblers
Here are some other nX-U8/100 disassemblers you should check out.

- [nxu8_disas](https://github.com/Fraserbc/nxu8_disas) by Fraser Price / Fraserbc / Delta / frsr
- [nX-U8-disassembler](https://github.com/lasnikr/nX-U8-disassembler) by Lasnikr (fork of nxu8_disas by Fraser Price)
- [nxu8_disas](https://github.com/LifeEmu/nxu8_disas) by LifeEmu (fork of nxu8_disas by Fraser Price)
