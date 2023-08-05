import os
import sys
import ctypes
import argparse
import traceback

class signed6(ctypes.Structure):
	_fields_ = [('value', ctypes.c_byte, 6)]

	def __init__(self, value: int = 0): self.value = value & 0x1f
	def __repr__(self): return f'signed6({self.value})'
	def __str__(self): return str(self.value)

stdout_file = None
input_file = None
addr = 0
labels = []
last_dsr_prefix = ''
last_dsr_prefix_str = ''

instructions = (
	((0xf, '#0', '#1', 6), 'ADD', 'ER#0', 'ER#1'),
	((0xe, '#0', 1, '#imm7'), 'ADD', 'ER#0', '#imm7'),
	((8, '#0', '#1', 1), 'ADD', 'R#0', 'R#1'),
	((1, '#0', '#imm8'), 'ADD', 'R#0', '#imm8'),
	((0xe, 1, '#signed8'), 'ADD', 'SP', '#signed8'),
	((8, '#0', '#1', 6), 'ADDC', 'R#0', 'R#1'),
	((6, '#0', '#imm8'), 'ADDC', 'R#0', '#imm8'),
	((8, '#0', '#1', 2), 'AND', 'R#0', 'R#1'),
	((2, '#0', '#imm8'), 'AND', 'R#0', '#imm8'),
	((2, '#Cadr', 0, 0), 'B', '#Cadr'),
	((0xf, 0, '#0', 2), 'B', 'ER#0'),
	((0xc, 0, '#Radr'), 'BGE', '#Radr'),
	((0xc, 1, '#Radr'), 'BLT', '#Radr'),
	((0xc, 2, '#Radr'), 'BGT', '#Radr'),
	((0xc, 3, '#Radr'), 'BLE', '#Radr'),
	((0xc, 4, '#Radr'), 'BGES', '#Radr'),
	((0xc, 5, '#Radr'), 'BLTS', '#Radr'),
	((0xc, 6, '#Radr'), 'BGTS', '#Radr'),
	((0xc, 7, '#Radr'), 'BLES', '#Radr'),
	((0xc, 8, '#Radr'), 'BNE', '#Radr'),
	((0xc, 9, '#Radr'), 'BEQ', '#Radr'),
	((0xc, 0xa, '#Radr'), 'BNV', '#Radr'),
	((0xc, 0xb, '#Radr'), 'BOV', '#Radr'),
	((0xc, 0xc, '#Radr'), 'BPS', '#Radr'),
	((0xc, 0xd, '#Radr'), 'BNS', '#Radr'),
	((0xc, 0xe, '#Radr'), 'BAL', '#Radr'),
	((0xf, '#Cadr', 0, 1), 'BL', '#Cadr'),
	((0xf, 0, '#1', 3), 'BL', 'ER#1'),
	((0xf, 0xf, 0xf, 0xf), 'BRK'),
	((0xf, '#0', '#1', 7), 'CMP', 'ER#0', 'ER#1'),
	((8, '#0', '#1', 7), 'CMP', 'R#0', 'R#1'),
	((7, '#0', '#imm8'), 'CMP', 'R#0', '#imm8'),
	((8, '#0', '#1', 5), 'CMPC', 'R#0', 'R#1'),
	((5, '#0', '#imm8'), 'CMPC', 'R#0', '#imm8'),
	((0xf, 0xe, 0xc, 0xf), 'CPLC'),
	((8, '#0', 1, 0xf), 'DAA', 'R#0'),
	((8, '#0', 3, 0xf), 'DAS', 'R#0'),
	((8, '#0', 3, 0xf), 'DEC', '#P[EA]'),
	((0xe, 0xb, 0xf, 7), 'DI'),
	((0xf, '#0', '#1', 9), 'DIV', 'ER#0', 'R#1'),
	((0x8, '#1+1', '#1', 0xf), 'EXTBW', 'ER#0'),
	((0xf, 0xe, 2, 0xf), 'INC', '#P[EA]'),
	((9, '#0', 3, 2), 'L', 'ER#0', '#P[EA]'),
	((9, '#0', 5, 2), 'L', 'ER#0', '#P[EA+]'),
	((9, '#0', '#1', 2), 'L', 'ER#0', '#P[ER#1]'),
	((0xa, '#0', '#1', 8), 'L', 'ER#0', '#P#Disp16[ER#1]'),
	((0xb, '#0', 0, '#Disp6'), 'L', 'ER#0', '#P#Disp6[BP]'),
	((0xb, '#0', 1, '#Disp6'), 'L', 'ER#0', '#P#Disp6[FP]'),
	((9, '#0', 1, 2), 'L', 'ER#0', '#P#Dadr'),
	((9, '#0', 3, 6), 'L', 'QR#0', '#P[EA]'),
	((9, '#0', 5, 6), 'L', 'QR#0', '#P[EA+]'),
	((9, '#0', 3, 0), 'L', 'R#0', '#P[EA]'),
	((9, '#0', 5, 0), 'L', 'R#0', '#P[EA+]'),
	((9, '#0', '#1', 0), 'L', 'R#0', '#P[ER#1]'),
	((9, '#0', '#1', 8), 'L', 'R#0', '#P#Disp16[ER#1]'),
	((0xd, '#0', 0, '#Disp6'), 'L', 'R#0', '#P#Disp6[BP]'),
	((0xd, '#0', 1, '#Disp6'), 'L', 'R#0', '#P#Disp6[FP]'),
	((9, '#0', 1, 0), 'L', 'R#0', '#P#Dadr'),
	((9, '#0', 3, 4), 'L', 'XR#0', '#P[EA]'),
	((9, '#0', 5, 4), 'L', 'XR#0', '#P[EA+]'),
	((0xf, 0, '#1', 0xa), 'LEA', '[ER#1]'),
	((0xf, 0, 0, 0xc), 'LEA', 'Dabr'),
	((0xf, 0, '#1', 0xb), 'LEA', 'Disp16[ER#1]'),
	((0xf, '#0', 2, 0xd), 'MOV', 'CER#0', '#P[EA]'),
	((0xf, '#0', 3, 0xd), 'MOV', 'CER#0', '#P[EA+]'),
	((0xf, '#0', 6, 0xd), 'MOV', 'CQR#0', '#P[EA]'),
	((0xf, '#0', 7, 0xd), 'MOV', 'CQR#0', '#P[EA+]'),
	((0xf, '#0', 0, 0xd), 'MOV', 'CR#0', '#P[EA]'),
	((0xf, '#0', 1, 0xd), 'MOV', 'CR#0', '#P[EA+]'),
	((0xa, '#0', '#1', 0xe), 'MOV', 'CR#0', 'R#1'),
	((0xf, '#0', 4, 0xd), 'MOV', 'CXR#0', '#P[EA]'),
	((0xf, '#0', 5, 0xd), 'MOV', 'CXR#0', '#P[EA+]'),
	((0xa, 0, '#1', 0xf), 'MOV', 'ECSR', 'R#1'),
	((0xa, '#0', 0, 0xd), 'MOV', 'ELR', 'ER#0'),
	((0xa, 0, '#1', 0xc), 'MOV', 'EPSW', 'R#1'),
	((0xa, '#0', 0, 5), 'MOV', 'ER#1', 'ELR'),
	((0xf, '#0', '#1', 5), 'MOV', 'ER#0', 'ER#1'),
	((0xf, '#0', 0, '#imm7'), 'MOV', 'ER#0', '#imm7'),
	((0xa, '#0', 1, 0xa), 'MOV', 'ER#0', 'SP'),
	((0xf, '#1', 0xa, 0xd), 'MOV', '#P[EA]', 'CER#1'),
	((0xf, '#1', 0xb, 0xd), 'MOV', '#P[EA+]', 'CER#1'),
	((0xf, '#1', 0xe, 0xd), 'MOV', '#P[EA]', 'CQR#1'),
	((0xf, '#1', 0xf, 0xd), 'MOV', '#P[EA+]', 'CQR#1'),
	((0xf, '#1', 8, 0xd), 'MOV', '#P[EA]', 'CR#1'),
	((0xf, '#1', 9, 0xd), 'MOV', '#P[EA+]', 'CR#1'),
	((0xf, '#1', 0xc, 0xd), 'MOV', '#P[EA]', 'CXR#1'),
	((0xf, '#1', 0xd, 0xd), 'MOV', '#P[EA+]', 'CXR#1'),
	((0xe, 9, '#unsigned8'), 'MOV', 'PSW', '#unsigned8'),
	((0xa, 0, '#1', 0xb), 'MOV', 'PSW', 'R#1'),
	((0xa, '#0', '#1', 6), 'MOV', 'R#0', 'CR#1'),
	((0xa, '#0', 0, 7), 'MOV', 'R#0', 'ECSR'),
	((0xa, '#0', 0, 4), 'MOV', 'R#0', 'EPSW'),
	((0xa, '#0', 0, 3), 'MOV', 'R#0', 'PSW'),
	((8, '#0', '#1', 0), 'MOV', 'R#0', 'R#1'),
	((0, '#0', '#imm8'), 'MOV', 'R#0', '#imm8'),
	((0xa, 1, '#1', 0xa), 'MOV', 'SP', 'ER#1'),
	((0xf, '#0', '#1', 4), 'MUL', 'ER#0', 'R#1'),
	((8, '#0', 5, 0xf), 'NEG', 'R#0'),
	((0xf, 0xe, 8, 0xf), 'NOP'),
	((8, '#0', '#1', 3), 'OR', 'R#0', 'R#1'),
	((3, '#0', '#imm8'), 'OR', 'R#0', '#imm8'),
	((0xf, 1, 8, 0xe), 'POP', 'EA'),
	((0xf, 2, 8, 0xe), 'POP', 'PC'),
	((0xf, 3, 8, 0xe), 'POP', 'EA, PC'),
	((0xf, 4, 8, 0xe), 'POP', 'PSW'),
	((0xf, 5, 8, 0xe), 'POP', 'EA, PSW'),
	((0xf, 6, 8, 0xe), 'POP', 'PC, PSW'),
	((0xf, 7, 8, 0xe), 'POP', 'EA, PC, PSW'),
	((0xf, 8, 8, 0xe), 'POP', 'LR'),
	((0xf, 9, 8, 0xe), 'POP', 'EA, LR'),
	((0xf, 0xa, 8, 0xe), 'POP', 'PC, LR'),
	((0xf, 0xb, 8, 0xe), 'POP', 'EA, PC, LR'),
	((0xf, 0xc, 8, 0xe), 'POP', 'PSW, LR'),
	((0xf, 0xd, 8, 0xe), 'POP', 'EA, PSW, LR'),
	((0xf, 0xe, 8, 0xe), 'POP', 'PC, PSW, LR'),
	((0xf, 0xf, 8, 0xe), 'POP', 'EA, PC, PSW, LR'),
	((0xf, '#0', 0, 0xe), 'POP', 'R#0'),
	((0xf, '#0', 1, 0xe), 'POP', 'ER#0'),
	((0xf, '#0', 2, 0xe), 'POP', 'XR#0'),
	((0xf, '#0', 3, 0xe), 'POP', 'QR#0'),
	((0xf, 1, 0xc, 0xe), 'PUSH', 'EA'),
	((0xf, 2, 0xc, 0xe), 'PUSH', 'PC'),
	((0xf, 3, 0xc, 0xe), 'PUSH', 'EA, PC'),
	((0xf, 4, 0xc, 0xe), 'PUSH', 'PSW'),
	((0xf, 5, 0xc, 0xe), 'PUSH', 'EA, PSW'),
	((0xf, 6, 0xc, 0xe), 'PUSH', 'PC, PSW'),
	((0xf, 7, 0xc, 0xe), 'PUSH', 'EA, PC, PSW'),
	((0xf, 8, 0xc, 0xe), 'PUSH', 'LR'),
	((0xf, 9, 0xc, 0xe), 'PUSH', 'EA, LR'),
	((0xf, 0xa, 0xc, 0xe), 'PUSH', 'PC, LR'),
	((0xf, 0xb, 0xc, 0xe), 'PUSH', 'EA, PC, LR'),
	((0xf, 0xc, 0xc, 0xe), 'PUSH', 'PSW, LR'),
	((0xf, 0xd, 0xc, 0xe), 'PUSH', 'EA, PSW, LR'),
	((0xf, 0xe, 0xc, 0xe), 'PUSH', 'PC, PSW, LR'),
	((0xf, 0xf, 0xc, 0xe), 'PUSH', 'EA, PC, PSW, LR'),
	((0xf, '#0', 4, 0xe), 'PUSH', 'R#0'),
	((0xf, '#0', 5, 0xe), 'PUSH', 'ER#0'),
	((0xf, '#0', 6, 0xe), 'PUSH', 'XR#0'),
	((0xf, '#0', 7, 0xe), 'PUSH', 'QR#0'),
	((0xa, 0, 1, 2), 'RB', '#P#Dadr.#bit_offset'),
	((0xa, '#0', 0, 2), 'RB', 'R#0.#bit_offset'),
	((0xe, 0xb, 7, 0xf), 'RC'),
	((0xf, 0xe, 1, 0xf), 'RT'),
	((0xf, 0xe, 0, 0xf), 'RTI'),
	((0xa, 0, 1, 0), 'SB', '#P#Dadr.#bit_offset'),
	((0xa, '#0', 1, 0), 'SB', 'R#0.#bit_offset'),
	((0xe, 0xd, 8, 0), 'SC'),
	((8, '#0', '#1', 0xa), 'SLL', 'R#0', 'R#1'),
	((9, '#0', 0, 0xa), 'SLL', 'R#0', '#width'),
	((8, '#0', '#1', 0xb), 'SLLC', 'R#0', 'R#1'),
	((9, '#0', 0, 0xb), 'SLLC', 'R#0', '#width'),
	((8, '#0', '#1', 0xe), 'SRA', 'R#0', 'R#1'),
	((9, '#0', 0, 0xe), 'SRA', 'R#0', '#width'),
	((8, '#0', '#1', 0xc), 'SRL', 'R#0', 'R#1'),
	((9, '#0', 0, 0xc), 'SRL', 'R#0', '#width'),
	((8, '#0', '#1', 0xd), 'SRLC', 'R#0', 'R#1'),
	((9, '#0', 0, 0xd), 'SRLC', 'R#0', '#width'),
	((9, '#0', 3, 3), 'ST', 'ER#0', '#P[EA]'),
	((9, '#0', 5, 3), 'ST', 'ER#0', '#P[EA+]'),
	((9, '#0', '#1', 3), 'ST', 'ER#0', '#P[ER#1]'),
	((0xa, '#0', '#1', 9), 'ST', 'ER#0', '#P#Disp16[ER#1]'),
	((0xb, '#0', 2, '#Disp6'), 'ST', 'ER#0', '#P#Disp6[BP]'),
	((0xb, '#0', 3, '#Disp6'), 'ST', 'ER#0', '#P#Disp6[FP]'),
	((9, '#0', 1, 3), 'ST', 'ER#0', '#P#Dadr'),
	((9, '#0', 3, 7), 'ST', 'QR#0', '#P[EA]'),
	((9, '#0', 5, 7), 'ST', 'QR#0', '#P[EA+]'),
	((9, '#0', 3, 1), 'ST', 'R#0', '#P[EA]'),
	((9, '#0', 5, 1), 'ST', 'R#0', '#P[EA+]'),
	((9, '#0', '#1', 1), 'ST', 'R#0', '#P[ER#1]'),
	((0x9, '#0', '#1', 9), 'ST', 'R#0', '#P#Disp16[ER#1]'),
	((0xd, '#0', 2, '#Disp6'), 'ST', 'R#0', '#P#Disp6[BP]'),
	((0xd, '#0', 3, '#Disp6'), 'ST', 'R#0', '#P#Disp6[FP]'),
	((9, '#0', 1, 1), 'ST', 'R#0', '#P#Dadr'),
	((9, '#0', 3, 5), 'ST', 'XR#0', '#P[EA]'),
	((9, '#0', 5, 5), 'ST', 'XR#0', '#P[EA+]'),
	((8, '#0', '#1', 8), 'SUB', 'R#0', 'R#1'),
	((8, '#0', '#1', 9), 'SUBC', 'R#0', 'R#1'),
	((8, '5', 0, '#snum'), 'SWI', '#snum'),
	((0xa, 0, 1, 1), 'TB', '#P#Dadr.#bit_offset'),
	((0xa, '#0', 0, 1), 'TB', 'R#0.#bit_offset'),
	((8, '#0', '#1', 4), 'XOR', 'R#0', 'R#1'),
	((4, '#0', '#imm8'), 'XOR', 'R#0', '#imm8'),
	)

dsr_prefixes = (
	((0xe, 3, '#pseg_addr'), '#pseg_addr'),
	((9, 0, '#d', 0xf), 'R#d'),
	((0xf, 0xe, 9, 0xf), 'DSR'),
	)

rst_vct_names = {0: 'spinit', 2: 'start', 4: 'brk', 6: 'nmice_entry', 8: 'nmi_entry'}
int_entry_name_template = 'Int{}_entry'
swi_entry_name_template = 'sw{}_entry'

def printf(*args, **kwargs): print(*args, **kwargs, file = stdout_file)

def conv_nibbs(data: bytes) -> tuple: return (data[0] >> 4) & 0xf, data[0] & 0xf, (data[1] >> 4) & 0xf, data[1] & 0xf

def comb_nibbs(data: tuple) -> int: return int(hex(data[0]) + hex(data[1])[2:], 16)

def format_hex(data: int) -> str: return format(data, '02X') + 'H'
def format_hex_sign(data: int) -> str: return format(data, '+X') + 'H'
def format_hex_w(data: int) -> str: return format(data, '04X') + 'H'
def format_hex_dd(data: int) -> str: return format(data, '08X') + 'H'

def conv_little(data: bytes) -> bytes: return bytes([c for t in zip(data[1::2], data[::2]) for c in t])

def fmt_addr(addr: int) -> str:
	csr = (addr & 0xFF0000) >> 16
	high = (addr & 0xFF00) >> 8
	low = addr & 0xFF
	return '{:02X}:{:02X}{:02X}H'.format(csr, high, low)

def decode_ins():
	global labels, last_dsr_prefix, addr

	ins_len = 2
	prefix_word, _ = read_ins()
	prefix_str = ''
	for prefix in dsr_prefixes:
		score = 0
		for i in range(len(prefix[0])):
			if type(prefix[0][i]) != int: continue
			elif prefix_word[i] == prefix[0][i]: score += 1
		if score > sum(isinstance(_, int) for _ in prefix[0]):
			prefix_str = prefix[1] + ':'
			ins_len += 2
			break
	prefix_str = prefix_str.replace('#pseg_addr', str(comb_nibbs(prefix_word[2:])))
	prefix_str = prefix_str.replace('#d', str(prefix_word[2]))

	if prefix_str: return prefix_str, ins_len, True, False

	word, raw_bytes = read_ins()
	raw_bytes_int = int.from_bytes(raw_bytes, 'big')
	ins_str = f'D{"W" if ins_len == 2 else "D"} {format_hex_w(raw_bytes_int) if ins_len == 2 else format_hex_dd(raw_bytes_int)}'
	for ins in instructions:
		score = 0
		for i in range(len(ins[0])):
			if type(ins[0][i]) != int: continue
			elif word[i] == ins[0][i]: score += 1
		num_ints = sum(isinstance(_, int) for _ in ins[0])
		if num_ints in (1, 4) or any(ins[1] == i for i in ('B', 'BL', 'POP', 'PUSH')) or any(i in j for i in ('#P[EA]', '#P[EA+]') for j in ins[2:]): score_cond = num_ints
		elif any(i in j for i in ('#width', '#imm7', '#Disp6', '#bit_offset') for j in ins[2:]): score_cond = 1
		else: score_cond = 2
		if score >= score_cond and word[0] == ins[0][0]:
			conditions = [ins[0][1] == '#1+1' and word[2] != ins[0][2], type(ins[0][-1]) == int and word[3] != ins[0][3]]
			if len(ins) > 2: conditions.extend((
				ins[2] == '#width' and (word[2] >> 3) != ins[0][2],
				ins[2] == '#imm7' and (word[2] >> 3) != ins[0][2],
				'ER#0' in ins[2] and (word[1] & 1) != 0,
				'XR#0' in ins[2] and (word[1] & 2) != 0,
				'QR#0' in ins[2] and (word[1] & 3) != 0,
				))
			if len(ins) > 3: conditions.extend((
				'ER#1' in ins[3] and (word[2] & 1) != 0,
				'XR#1' in ins[3] and (word[2] & 2) != 0,
				'QR#1' in ins[3] and (word[2] & 3) != 0,
				'#Disp6' in ins[3] and (word[2] >> 2) != ins[0][2],
				'#bit_offset' in ins[3] and (word[2] >> 3) != ins[0][2],
				))

			if not any(conditions):
				ins_str = ins[1]
				if len(ins) >= 3: ins_str += ' ' + ins[2]
				if len(ins) >= 4: ins_str += ', ' + ins[3]
				break

	if '#Dadr' in ins_str:
		addr_temp = addr; addr += 2
		_, raw_bytes2 = read_ins()
		addr = addr_temp
		ins_len += 2
		ins_str = ins_str.replace('#Dadr', f'{format(word[1], "X")}:{format_hex_w(int.from_bytes(raw_bytes2, "big"))}')

	if '#Disp16' in ins_str:
		addr_temp = addr; addr += 2
		_, raw_bytes2 = read_ins()
		addr = addr_temp
		ins_len += 2
		ins_str = ins_str.replace('#Disp16', format_hex_sign(ctypes.c_short(int.from_bytes(raw_bytes2, "big")).value))

	if '#Cadr' in ins_str:
		addr_temp = addr; addr += 2
		_, raw_bytes2 = read_ins()
		addr = addr_temp
		ins_len += 2
		cadr = word[1] * 0x10000 + int.from_bytes(raw_bytes2, 'big')
		if cadr % 2 != 0: cadr -= 1
		if cadr > 5 and cadr < len(input_file):
			skip = False
			for label in labels:
				if label[1] == cadr:
					skip = True
					label_name = label[0]
					break
			if not skip:
				label_name = f'f_{format(cadr, "05X")}'
				labels.append((label_name, cadr, True))
			ins_str = ins_str.replace('#Cadr', label_name)
		else: ins_str = ins_str.replace('#Cadr', fmt_addr(cadr))

	if '#Radr' in ins_str:
		radr = addr + ins_len + ctypes.c_byte(comb_nibbs(word[2:])).value * 2
		if radr > 5 and radr < len(input_file):
			skip = False
			for label in labels:
				if label[1] == radr:
					skip = True
					label_name = label[0]
					break
			if not skip:
				label_name = f'.skip_{format(radr, "04x")}'
				labels.append((label_name, radr, False))
			ins_str = ins_str.replace('#Radr', label_name)
		else: ins_str = ins_str.replace('#Radr', fmt_addr(radr)[1:])

	if '#P' in ins_str:
		used_dsr_prefix = bool(last_dsr_prefix)
		ins_len + 2
		ins_str = ins_str.replace('#P', last_dsr_prefix)
		last_dsr_prefix = ''
		last_dsr_prefix_str = ''
	else: used_dsr_prefix = False

	ins_str = ins_str.replace('#0', str(word[1]))
	ins_str = ins_str.replace('#1', str(word[2]))
	ins_str = ins_str.replace('#bit_offset', str(word[2] & 7))
	ins_str = ins_str.replace('#imm8', f'#{format_hex(comb_nibbs(word[2:]))}')
	ins_str = ins_str.replace('#unsigned8', f'#{format_hex(comb_nibbs(word[2:]))}')
	ins_str = ins_str.replace('#signed8', format_hex_sign(ctypes.c_byte(comb_nibbs(word[2:])).value))
	ins_str = ins_str.replace('#imm7', f'#{format_hex(comb_nibbs((word[2] & 7, word[3])))}')
	ins_str = ins_str.replace('#width', str(word[2] & 7))
	ins_str = ins_str.replace('#Disp6', format_hex_sign(signed6(comb_nibbs((word[2] & 3, word[3]))).value))
	ins_str = ins_str.replace('#snum', str(comb_nibbs((word[2] & 3, word[3]))))

	return ins_str, ins_len, False, used_dsr_prefix

def read_ins() -> tuple:
	global addr, input_file
	byte = input_file[addr:addr+2][::-1]
	return conv_nibbs(byte), byte

def disassemble(interrupts: bool = True):
	global addr, input_file, labels, rst_vct_names, last_dsr_prefix, last_dsr_prefix_str
	vct_table_lines = {}
	lines = {}

	tab = '\t'
	format_ins = lambda addr, ins_op, ins_len, ins_str: f'{fmt_addr(addr)}\t{format(ins_op, "0"+str(ins_len*2)+"X")}\t{tab if ins_len < 3 else ""}{ins_str}'
	get_op = lambda addr, length = 2: int.from_bytes(conv_little(input_file[addr:addr+length]), 'big')

	while addr < 10 if interrupts else 6:	
		ins_op = get_op(addr)
		vct_table_lines[addr] = format_ins(addr, ins_op, 2, f'DW {rst_vct_names[addr]}')
		addr += 2

	if interrupts:
		for i in range(1, 60):	
			ins_op = get_op(addr)
			vct_table_lines[addr] = format_ins(addr, ins_op, 2, f'DW {int_entry_name_template.format(i)}')
			addr += 2

		for i in range(64):	
			ins_op = get_op(addr)
			vct_table_lines[addr] = format_ins(addr, ins_op, 2, f'DW {swi_entry_name_template.format(i)}')
			addr += 2

	for k, v in rst_vct_names.items(): labels.append((v, int.from_bytes(conv_little(input_file[k:k+2]), 'big'), True))

	while addr < len(input_file):
		ins_str, ins_len, dsr_prefix, used_dsr_prefix = decode_ins()
		ins_op = get_op(addr, ins_len)
		if dsr_prefix:
			if last_dsr_prefix:
				lines[addr] = format_ins(addr, get_op(addr), 2, f'DW {format_hex_w(ins_op)}')
				lines[addr_prev] = format_ins(addr_prev, get_op(addr_prev), 2, last_dsr_prefix_str)
			else:
				last_dsr_prefix = ins_str
				last_dsr_prefix_str = f'DW {format_hex_w(ins_op)}'
				addr_prev = addr
		else:
			lines[addr] = format_ins(addr, ins_op, ins_len + (2 if used_dsr_prefix else 0), ins_str)
			if last_dsr_prefix: format_ins(addr_prev, get_op(addr_prev), 2, ins_str)
		addr += ins_len

	end_func_lines = ('POP PC', 'RT', 'RTI', 'BAL')
	for k, v in lines.items():
		label_found = False
		if any(j in v for j in end_func_lines):
			for label in labels:
				if label[1] == k+2:
					label_found = True
					if label[2]: lines[k] += '\n'
					break
			if not label_found:
				labels.append((f'f_{format(k+2, "05X")}_UNUSED', k+2, True))
				lines[k] += '\n'

	for label in tuple(dict.fromkeys(labels)):
		if label[1] in lines: lines[label[1]] = f'{label[0]}:\n' + lines[label[1]]

	if stdout_file: printf('''\
; This file was generated by PyU8disas
; GitHub repository: https://github.com/gamingwithevets/pyu8disas
''')
	printf('; Reset vectors')
	for k, v in rst_vct_names.items():
		if k == 6:
			if not interrupts: break
			else: printf('\n; Hardware interrupt vectors')
		printf(f'{v} = {format_hex_w(get_op(k))}')
	if interrupts:
		for i in range(1, 60):
			ptr_val = 8 + i*2
			printf(f'{int_entry_name_template.format(i)} = {format_hex_w(get_op(ptr_val))}')
		printf('\n; Software interrupt vectors')
		for i in range(64):
			ptr_val = 0x80 + i*2
			printf(f'{swi_entry_name_template.format(i)} = {format_hex_w(get_op(ptr_val))}')

	printf('\n' + '\n'.join(vct_table_lines.values()) + '\n')
	printf('\n'.join(lines.values()))

if __name__ == '__main__':
	parser = argparse.ArgumentParser(description = 'PyU8disas - nX-U8 disassembler. Outputs assembly format.', epilog = '(c) 2023 GamingWithEvets Inc.\nLicensed under the MIT license', formatter_class=argparse.RawTextHelpFormatter, allow_abbrev = False)
	parser.add_argument('input', help = 'name of binary file (must have even length)')
	parser.add_argument('-n', '--ignore-interrupts', dest = 'interrupts', action = 'store_false', help = 'treat the interrupt vector area as normal code')
	parser.add_argument('-o', '--output', metavar = 'output', help = 'name of output file. if omitted the disassembly will be outputted to stdout')
	args = parser.parse_args()
	if args.output: stdout_file = open(args.output, 'w+')
	input_file = open(args.input, 'rb').read()
	if len(input_file) % 2 != 0: parser.error('binary file must be of even length')
	try: disassemble(args.interrupts)
	except Exception:
		if args.output: printf('''\
; This file was generated by PyU8disas
; GitHub repository: https://github.com/gamingwithevets/pyu8disas

; Unfortunately, an exception was thrown during the disassembly process. The
; exception details are provided below for reference.

; ''' + '\n; '.join(traceback.format_exc().split('\n')))
		print(traceback.format_exc())
	except KeyboardInterrupt:
		print('KeyboardInterrupt detected, exiting.')
		printf('''\
; This file was generated by PyU8disas
; GitHub repository: https://github.com/gamingwithevets/pyu8disas

; The disassembly process was interrupted.\
''')
