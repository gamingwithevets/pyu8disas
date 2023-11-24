**PyU8disas** is an nX-U8/100 core disassembler written in Python. It tries to mimic the original, intended assembly syntax of the U8 architecture.

# Features
- **Automatic labels**
  - PyU8disas can detect function calls and jump instructions, and label functions and jump addresses accordingly.
- **Unused function detection**
  - If PyU8disas detects a function that is never called or jumped to, it considers the function unused. Note that **PyU8disas does not search for function tables**, so any function called from a jump table may be mislabeled as unused. 
- **Labels file loading**
  - PyU8disas can load a provided labels file and insert the labels into the disassembly. See user202729's labels files as a reference to create your own labels files.

# Usage
```
usage: main.py [-h] [-a] [-u] [-t] [-l LABELS] [-o output] [-d] input

positional arguments:
  input                 name of binary file (must have even length)

options:
  -h, --help            show this help message and exit
  -a, --hide-addresses  hide addresses and operands in disassembly
  -u, --no-unused       don't add the _UNUSED suffix for unused functions
  -t, --no-auto-labels  don't generate local label names
  -l [labels ...], --labels [labels ...]
                        path to label files
  -s start, --start start
                        start address (must be even and hexadecimal)
  -n, --no-vct          disable the vector table
  -o output, --output output
                        name of output file (default = 'disas.asm')
  -d, --debug           enable debug logs
```

# Other U8 disassemblers
Here are some other nX-U8/100 disassemblers you should check out.

- [nxu8_disas](https://github.com/Fraserbc/nxu8_disas) by Fraser Price / Fraserbc / Delta / frsr
- [nX-U8-disassembler](https://github.com/lasnikr/nX-U8-disassembler) by Lasnikr (fork of nxu8_disas by Fraser Price)
- [nxu8_disas](https://github.com/LifeEmu/nxu8_disas) by LifeEmu (fork of nxu8_disas by Fraser Price)
