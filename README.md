**PyU8disas** is an nX-U8/100 disassembler written in Python. It tries to mimic the original, intended ASM syntax of the U8 architecture.

# Usage
```
usage: main.py [-h] [-n] [-o output] input

positional arguments:
  input                 name of binary file (must have even length)

options:
  -h, --help            show this help message and exit
  -n, --ignore-interrupts
                        treat the interrupt vector area as normal code
  -o output, --output output
                        name of output file. if omitted the disassembly will be outputted to stdout

```

# Similar tools
Here are some other nX-U8/100 disassemblers you should check out.

- [nxu8_disas](https://github.com/Fraserbc/nxu8_disas) by Fraser Price / Fraserbc / Delta / frsr
- [nX-U8-disassembler](https://github.com/lasnikr/nX-U8-disassembler) by Lasnikr (fork of nxu8_disas by Fraser Price)
- [nxu8_disas](https://github.com/LifeEmu/nxu8_disas) by LifeEmu (fork of nxu8_disas by Fraser Price)
