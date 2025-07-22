# Copyright (c) 2025 Daniel Roethlisberger
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.


import binaryninja as binja

import struct
import sys
import traceback

from dataclasses import dataclass


def _LowLevelILFunction_label_for_address(self, addr):
    """
    Get the label for an absolute virtual memory address, creating the label if
    it does not exist yet.
    """
    label = self.get_label_for_address(self.arch, addr)
    if label is None:
        self.add_label_for_address(self.arch, addr)
        label = self.get_label_for_address(self.arch, addr)
    assert label is not None
    return label
binja.LowLevelILFunction.x_label_for_address = _LowLevelILFunction_label_for_address


def _LowLevelILLabel___str__(self):
    return f"LowLevelILLabel(operand={self.operand}, ref={self.ref}, resolved={self.resolved})"
binja.LowLevelILLabel.__str__ = _LowLevelILLabel___str__


def _BinaryView_load_types(self, typeid, source):
    types = self.parse_types_from_string(source)
    self.define_types([(binja.Type.generate_auto_type_id(typeid, k), k, v) for k, v in types.types.items()], None)
binja.BinaryView.x_load_types = _BinaryView_load_types


_TYPE_ID_SOURCE = "binja-bpf"

_TYPE_SOURCE = """
struct eth_hdr __packed {
    uint8_t     eth_dst[6];
    uint8_t     eth_src[6];
    uint16_t    eth_type;
};

struct ip_hdr __packed {
    uint8_t     ip_vhl;
    uint8_t     ip_tos;
    uint16_t    ip_len;
    uint16_t    ip_id;
    uint16_t    ip_off;
    uint8_t     ip_ttl;
    uint8_t     ip_p;
    uint16_t    ip_sum;
    uint32_t    ip_src;
    uint32_t    ip_dst;
};

struct ip6_hdr __packed {
    uint32_t    ip6_vtcfl;
    uint16_t    ip6_plen;
    uint8_t     ip6_nxt;
    uint8_t     ip6_hlim;
    uint128_t   ip6_src;
    uint128_t   ip6_dst;
};

struct udp_hdr __packed {
    uint16_t udp_sport;
    uint16_t udp_dport;
    uint16_t udp_len;
    uint16_t udp_chksum;
};

struct tcp_hdr __packed {
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint32_t tcp_seq;
    uint32_t tcp_ack;
    uint16_t tcp_flags;
    uint16_t tcp_win;
    uint16_t tcp_chksum;
    uint16_t tcp_urgptr;
};

struct ip_packet __packed {
    union
    {
        struct {
            struct ip_hdr ip;
            union {
                struct tcp_hdr tcp;
                struct udp_hdr udp;
            };
        };
        struct {
            struct ip6_hdr ip6;
            union {
                struct tcp_hdr tcp6;
                struct udp_hdr udp6;
            };
        };
    };
};

struct ether_packet __packed
{
    struct eth_hdr eth;
    union
    {
        struct {
            struct ip_hdr ip;
            union {
                struct tcp_hdr tcp;
                struct udp_hdr udp;
            };
        };
        struct {
            struct ip6_hdr ip6;
            union {
                struct tcp_hdr tcp6;
                struct udp_hdr udp6;
            };
        };
    };
};
"""


BPF_MAXINSNS    = 4096
BPF_MEMWORDS    = 16

BPF_CLASS_MASK  = 0x07
BPF_LD          = 0x00
BPF_LDX         = 0x01
BPF_ST          = 0x02
BPF_STX         = 0x03
BPF_ALU         = 0x04
BPF_JMP         = 0x05
BPF_RET         = 0x06
BPF_MISC        = 0x07

# ld, ldx
BPF_SIZE_MASK   = 0x18
BPF_W           = 0x00
BPF_H           = 0x08
BPF_B           = 0x10

# ld, ldx
BPF_MODE_MASK   = 0xe0
BPF_IMM         = 0x00
BPF_ABS         = 0x20
BPF_IND         = 0x40
BPF_MEM         = 0x60
BPF_LEN         = 0x80
BPF_MSH         = 0xa0
BPF_RND         = 0xc0 # OpenBSD

# alu
BPF_ALUOP_MASK  = 0xf0
BPF_ADD         = 0x00
BPF_SUB         = 0x10
BPF_MUL         = 0x20
BPF_DIV         = 0x30
BPF_OR          = 0x40
BPF_AND         = 0x50
BPF_LSH         = 0x60
BPF_RSH         = 0x70
BPF_NEG         = 0x80
BPF_MOD         = 0x90 # FreeBSD, Linux
BPF_XOR         = 0xa0 # FreeBSD, Linux

# jmp
BPF_JMPOP_MASK  = 0xf0
BPF_JA          = 0x00
BPF_JEQ         = 0x10
BPF_JGT         = 0x20
BPF_JGE         = 0x30
BPF_JSET        = 0x40

# alu, jmp
BPF_SRC_MASK    = 0x08
BPF_K           = 0x00
BPF_X           = 0x08

# ret
BPF_RVAL_MASK   = 0x18
assert BPF_K == 0x00
BPF_A           = 0x10

# misc
BPF_MISCOP_MASK = 0xf8
BPF_TAX         = 0x00
BPF_COP         = 0x20 # NetBSD
BPF_COPX        = 0x40 # NetBSD
BPF_TXA         = 0x80


class BPFInstruction:
    class InvalidInstructionError(Exception):
        pass

    INSN_SIZE = 8

    _WIDTH_MAP = {
        BPF_W: 4,
        BPF_H: 2,
        BPF_B: 1,
    }

    _ALU_MNEMONIC_MAP = {
        BPF_NEG: "neg", # unused
        BPF_ADD: "add",
        BPF_SUB: "sub",
        BPF_MUL: "mul",
        BPF_DIV: "div",
        BPF_AND: "and",
        BPF_OR: "or",
        BPF_LSH: "lsh",
        BPF_RSH: "rsh",
        BPF_MOD: "mod",
        BPF_XOR: "xor",
    }

    _JMP_MNEMONIC_MAP = {
        BPF_JA: "ja", # unused
        BPF_JGT: "jgt",
        BPF_JGE: "jge",
        BPF_JEQ: "jeq",
        BPF_JSET: "jset",
    }

    def __init__(self, data, addr, endianness=binja.Endianness.LittleEndian):
        if (addr % BPFInstruction.INSN_SIZE) != 0:
            raise BPFInstruction.InvalidInstructionError(f"Misaligned address {addr:#06x}")
        if len(data) < BPFInstruction.INSN_SIZE:
            raise BPFInstruction.InvalidInstructionError(f"Buffer smaller than min insn length")

        if endianness == binja.Endianness.LittleEndian:
            layout = '<HBBI'
        elif endianness == binja.Endianness.BigEndian:
            layout = '>HBBI'
        self.code, self.jt, self.jf, self.k = struct.unpack(layout, data[:BPFInstruction.INSN_SIZE])

        self.bpf_class = self.code & BPF_CLASS_MASK
        if self.bpf_class in (BPF_LD, BPF_LDX):
            self.bpf_mode = self.code & BPF_MODE_MASK
            self.bpf_size = self.code & BPF_SIZE_MASK
            self.ld_width = BPFInstruction._WIDTH_MAP.get(self.bpf_size, None)
        elif self.bpf_class == BPF_ALU:
            self.bpf_aluop = self.code & BPF_ALUOP_MASK
            self.alu_mnemonic = BPFInstruction._ALU_MNEMONIC_MAP.get(self.bpf_aluop, None)
            self.bpf_src = self.code & BPF_SRC_MASK
        elif self.bpf_class == BPF_JMP:
            self.bpf_jmpop = self.code & BPF_JMPOP_MASK
            self.jmp_mnemonic = BPFInstruction._JMP_MNEMONIC_MAP.get(self.bpf_jmpop, None)
            self.bpf_src = self.code & BPF_SRC_MASK
        elif self.bpf_class == BPF_RET:
            self.bpf_rval = self.code & BPF_RVAL_MASK
        elif self.bpf_class == BPF_MISC:
            self.bpf_miscop = self.code & BPF_MISCOP_MASK

        if (err := self.validate()) is not None:
            raise BPFInstruction.InvalidInstructionError(err)

    def jmp_target_ja(self, pc):
        assert self.bpf_class == BPF_JMP and self.bpf_jmpop == BPF_JA
        return pc + BPFInstruction.INSN_SIZE + self.k * BPFInstruction.INSN_SIZE

    def jmp_target_jxx(self, pc):
        assert self.bpf_class == BPF_JMP and self.bpf_jmpop != BPF_JA
        target_true = pc + BPFInstruction.INSN_SIZE + self.jt * BPFInstruction.INSN_SIZE
        target_false = pc + BPFInstruction.INSN_SIZE + self.jf * BPFInstruction.INSN_SIZE
        return target_true, target_false

    def validate(self):
        if self.bpf_class == BPF_LD:
            if self.bpf_mode == BPF_IMM:
                if self.code != self.bpf_class + self.bpf_mode:
                    return f"Unexpected bits set in ld imm opcode {self.code:#04x}"
            elif self.bpf_mode == BPF_MEM:
                if self.code != self.bpf_class + self.bpf_mode:
                    return f"Unexpected bits set in ld mem opcode {self.code:#04x}"
                if self.k >= BPF_MEMWORDS:
                    return f"Immediate index k into M out of bounds {self.k}"
            elif self.bpf_mode == BPF_LEN:
                # BPF_W is 0
                if self.code != self.bpf_class + self.bpf_mode + BPF_W:
                    return f"Unexpected bits set in ld len opcode {self.code:#04x}"
            elif self.bpf_mode == BPF_ABS:
                if self.code != self.bpf_class + self.bpf_mode + self.bpf_size:
                    return f"Unexpected bits set in ld abs opcode {self.code:#04x}"
            elif self.bpf_mode == BPF_IND:
                if self.code != self.bpf_class + self.bpf_mode + self.bpf_size:
                    return f"Unexpected bits set in ld ind opcode {self.code:#04x}"
            elif self.bpf_mode == BPF_RND:
                # BPF_W is 0
                if self.code != self.bpf_class + self.bpf_mode + BPF_W:
                    return f"Unexpected bits set in ld rnd opcode {self.code:#04x}"
            else:
                return f"Unknown ld opcode {self.code:#04x}"
        elif self.bpf_class == BPF_LDX:
            if self.bpf_mode == BPF_IMM:
                # BPF_W is 0
                if self.code != self.bpf_class + self.bpf_mode + BPF_W:
                    return f"Unexpected bits set in ldx imm opcode {self.code:#04x}"
            elif self.bpf_mode == BPF_MEM:
                # BPF_W is 0
                if self.code != self.bpf_class + self.bpf_mode + BPF_W:
                    return f"Unexpected bits set in ldx mem opcode {self.code:#04x}"
                if self.k >= BPF_MEMWORDS:
                    return f"Immediate index k into M out of bounds {self.k}"
            elif self.bpf_mode == BPF_LEN:
                # BPF_W is 0
                if self.code != self.bpf_class + self.bpf_mode + BPF_W:
                    return f"Unexpected bits set in ldx len opcode {self.code:#04x}"
            elif self.bpf_mode == BPF_MSH:
                if self.code != self.bpf_class + self.bpf_mode + BPF_B:
                    return f"Unexpected bits set in ldx msh opcode {self.code:#04x}"
            else:
                return f"Unknown ldx opcode {self.code:#04x}"
        elif self.bpf_class == BPF_ST:
            if self.code != self.bpf_class:
                return f"Unexpected bits set in st opcode {self.code:#04x}"
            if self.k >= BPF_MEMWORDS:
                return f"Immediate index k into M out of bounds {self.k}"
        elif self.bpf_class == BPF_STX:
            if self.code != self.bpf_class:
                return f"Unexpected bits set in stx opcode {self.code:#04x}"
            if self.k >= BPF_MEMWORDS:
                return f"Immediate index k into M out of bounds {self.k}"
        elif self.bpf_class == BPF_ALU:
            if self.bpf_aluop == BPF_NEG:
                if self.code != self.bpf_class + self.bpf_aluop:
                    return f"Unexpected bits set in alu neg opcode {self.code:#04x}"
            else:
                if self.code != self.bpf_class + self.bpf_aluop + self.bpf_src:
                    return f"Unexpected bits set in alu opcode {self.code:#04x}"
                if self.bpf_aluop not in (BPF_ADD, BPF_SUB, BPF_MUL, BPF_DIV, BPF_AND,
                                          BPF_OR, BPF_LSH, BPF_RSH, BPF_MOD, BPF_XOR):
                    return f"Unknown alu op in opcode {self.code:#04x}"
        elif self.bpf_class == BPF_JMP:
            if self.bpf_jmpop == BPF_JA:
                if self.code != self.bpf_class + self.bpf_jmpop:
                    return f"Unexpected bits set in ja opcode {self.code:#04x}"
            else:
                if self.code != self.bpf_class + self.bpf_jmpop + self.bpf_src:
                    return f"Unexpected bits set in jxx opcode {self.code:#04x}"
        elif self.bpf_class == BPF_RET:
            if self.code != self.bpf_class + self.bpf_rval:
                return f"Unexpected bits set in ret opcode {self.code:#04x}"
            if self.bpf_rval not in (BPF_A, BPF_K):
                return f"Unexpected rval {self.bpf_rval:#04x} in ret opcode {self.code:#04x}"
        elif self.bpf_class == BPF_MISC:
            if self.code != self.bpf_class + self.bpf_miscop:
                return f"Unexpected bits set in misc opcode {self.code:#04x}"
            if self.bpf_miscop not in (BPF_TAX, BPF_TXA, BPF_COP, BPF_COPX):
                return f"Unknown misc opcode {self.code:#04x}"
        else:
            return f"Unknown class {self.bpf_class:#04x} in opcode {self.code:#04x}"
        return None


class RegisterCallingConventionMixin:
    @classmethod
    def register(cls):
        for arch_cls in (BPFLEArch, BPFBEArch):
            arch = binja.Architecture[arch_cls.name]
            obj = cls(arch, cls.name)
            arch.register_calling_convention(obj)
            arch.default_calling_convention = obj


class BPFMainCallingConvention(binja.CallingConvention, RegisterCallingConventionMixin):
    name = 'BPFMain'
    int_arg_regs = ["P", "len"]
    int_return_reg = "A"


class BPFArch(binja.Architecture):
    address_size = 4
    default_int_size = 4
    instr_alignment = BPFInstruction.INSN_SIZE
    max_instr_length = BPFInstruction.INSN_SIZE

    regs = {
        'pc': binja.RegisterInfo('pc', 4), # program counter
        'sp': binja.RegisterInfo('sp', 4), # unused

        'A': binja.RegisterInfo('A', 4), # accumulator
        'X': binja.RegisterInfo('X', 4), # index register

        'P': binja.RegisterInfo('P', 4), # packet pointer
        'len': binja.RegisterInfo('len', 4), # packet length

        # Memory slots modelled as register bank
        **{f'M{i}': binja.RegisterInfo(f'M{i}', 4) for i in range(BPF_MEMWORDS)},
    }
    stack_pointer = 'sp'

    def get_instruction_info(self, data, addr):
        try:
            insn = BPFInstruction(data, addr, self.endianness)
        except BPFInstruction.InvalidInstructionError as e:
            #print("*** get_instruction_info", data[0:8], f"{addr:#06x}")
            raise

        info = binja.InstructionInfo(length=BPFInstruction.INSN_SIZE)
        if insn.bpf_class == BPF_JMP:
            if insn.bpf_jmpop == BPF_JA:
                t = insn.jmp_target_ja(addr)
                info.add_branch(binja.BranchType.UnconditionalBranch, t)
            else:
                tt, tf = insn.jmp_target_jxx(addr)
                info.add_branch(binja.BranchType.TrueBranch, tt)
                info.add_branch(binja.BranchType.FalseBranch, tf)
        elif insn.bpf_class == BPF_RET:
            info.add_branch(binja.BranchType.FunctionReturn)
        return info

    def get_instruction_text(self, data, addr):
        try:
            insn = BPFInstruction(data, addr, self.endianness)
        except BPFInstruction.InvalidInstructionError as e:
            #print("*** get_instruction_text", data[0:8], f"{addr:#06x}")
            raise

        if insn.bpf_class == BPF_LD:
            tokens = [
                binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "mov"),
                binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "A"),
                binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
            ]
            if insn.bpf_mode == BPF_IMM:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.k:#x}"),
                ]
            elif insn.bpf_mode == BPF_MEM:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, f"M{insn.k}"),
                ]
            elif insn.bpf_mode == BPF_LEN:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "len"),
                ]
            elif insn.bpf_mode == BPF_ABS:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "P"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.BeginMemoryOperandToken, "["),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.k:#x}"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, ":"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.ld_width}"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.EndMemoryOperandToken, "]"),
                ]
            elif insn.bpf_mode == BPF_IND:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "P"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.BeginMemoryOperandToken, "["),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "X"),
                ]
                if insn.k != 0:
                    tokens += [
                        binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, "+"),
                        binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.k:#x}"),
                    ]
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, ":"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.ld_width}"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.EndMemoryOperandToken, "]"),
                ]
            elif insn.bpf_mode == BPF_RND:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, "arc4random()"),
                ]
        elif insn.bpf_class == BPF_LDX:
            tokens = [
                binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "mov"),
                binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "X"),
                binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
            ]
            if insn.bpf_mode == BPF_IMM:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.k:#x}"),
                ]
            elif insn.bpf_mode == BPF_MEM:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, f"M{insn.k}"),
                ]
            elif insn.bpf_mode == BPF_LEN:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "len"),
                ]
            elif insn.bpf_mode == BPF_MSH:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, "4"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, "*("),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "P"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.BeginMemoryOperandToken, "["),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.k:#x}"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, ":"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.ld_width}"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.EndMemoryOperandToken, "]"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, "&"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"0x0f"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, ")"),
                ]
        elif insn.bpf_class == BPF_ST:
            tokens = [
                binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "mov"),
                binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, f"M{insn.k}"),
                binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "A"),
            ]
        elif insn.bpf_class == BPF_STX:
            tokens = [
                binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "mov"),
                binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, f"M{insn.k}"),
                binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "X"),
            ]
        elif insn.bpf_class == BPF_ALU:
            if insn.bpf_aluop == BPF_NEG:
                tokens = [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "neg"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "A"),
                ]
            else:
                tokens = [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, insn.alu_mnemonic),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "A"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                ]
                if insn.bpf_src == BPF_K:
                    tokens += [
                        binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.k:#x}"),
                    ]
                elif insn.bpf_src == BPF_X:
                    tokens += [
                        binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "X"),
                    ]
        elif insn.bpf_class == BPF_JMP:
            if insn.bpf_jmpop == BPF_JA:
                target = insn.jmp_target_ja(addr)
                tokens = [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "ja"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.PossibleAddressToken, f"{target:#x}"),
                ]
            else:
                target_true, target_false = insn.jmp_target_jxx(addr)
                tokens = [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, insn.jmp_mnemonic),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "A"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                ]
                if insn.bpf_src == BPF_K:
                    tokens += [
                        binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.k:#x}"),
                    ]
                elif insn.bpf_src == BPF_X:
                    tokens += [
                        binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "X"),
                    ]
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.PossibleAddressToken, f"{target_true:#x}"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.PossibleAddressToken, f"{target_false:#x}"),
                ]
        elif insn.bpf_class == BPF_RET:
            tokens = [
                binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "ret"),
                binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
            ]
            if insn.bpf_rval == BPF_A:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "A"),
                ]
            elif insn.bpf_rval == BPF_K:
                tokens += [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.k:#x}"),
                ]
        elif insn.bpf_class == BPF_MISC:
            if insn.bpf_miscop == BPF_TAX:
                tokens = [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "mov"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "X"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "A"),
                ]
            elif insn.bpf_miscop == BPF_TXA:
                tokens = [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "mov"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "A"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "X"),
                ]
            elif insn.bpf_miscop == BPF_COP:
                tokens = [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "cop"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "A"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.IntegerToken, f"{insn.k:#x}"),
                ]
            elif insn.bpf_miscop == BPF_COPX:
                tokens = [
                    binja.InstructionTextToken(binja.InstructionTextTokenType.InstructionToken, "cop"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "A"),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.OperandSeparatorToken, ","),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.TextToken, " "),
                    binja.InstructionTextToken(binja.InstructionTextTokenType.RegisterToken, "X"),
                ]
        return tokens, BPFInstruction.INSN_SIZE

    def _load_from_P(self, il, width, offset, *, index=False):
        """
        Emit LLIL to load a value of given width from packet data buffer
        pointed to by register P, with offset, optionally adding value of
        register X to offset.
        """
        if index:
            op_r = il.add(4, il.reg(4, "X"),
                             il.const(4, offset))
        else:
            op_r = il.const(4, offset)
        addr = il.add(4, il.reg(4, "P"), op_r)
        value = il.load(width, addr)
        if width < 4:
            value = il.zero_extend(4, value)
        return value

    def get_instruction_low_level_il(self, data, addr, il):
        #print("*** instructions count", len(il), "il.source_function", il.source_function)
        try:
            insn = BPFInstruction(data, addr, self.endianness)
        except BPFInstruction.InvalidInstructionError as e:
            #print("*** get_instruction_low_level_il", data[0:8], f"{addr:#06x}")
            raise

        if insn.bpf_class == BPF_LD:
            if insn.bpf_mode == BPF_IMM:
                value = il.const(4, insn.k)
            elif insn.bpf_mode == BPF_MEM:
                value = il.reg(4, f"M{insn.k}")
            elif insn.bpf_mode == BPF_LEN:
                value = il.reg(4, "len")
            elif insn.bpf_mode == BPF_ABS:
                value = self._load_from_P(il, insn.ld_width, insn.k)
            elif insn.bpf_mode == BPF_IND:
                value = self._load_from_P(il, insn.ld_width, insn.k, index=True)
            elif insn.bpf_mode == BPF_RND:
                temp_reg = binja.LLIL_TEMP(il.temp_reg_count)
                il.append(il.intrinsic([binja.ILRegister(il.arch, temp_reg)], 'arc4random', []))
                value = il.reg(4, temp_reg)
            il.append(il.set_reg(4, "A", value))
        elif insn.bpf_class == BPF_LDX:
            if insn.bpf_mode == BPF_IMM:
                value = il.const(4, insn.k)
            elif insn.bpf_mode == BPF_MEM:
                value = il.reg(4, f"M{insn.k}")
            elif insn.bpf_mode == BPF_LEN:
                value = il.reg(4, "len")
            elif insn.bpf_mode == BPF_MSH:
                value = il.mult(4, il.const(4, 4),
                                   il.and_expr(4, il.const(4, 0x0f),
                                                  self._load_from_P(il, 1, insn.k)))
            il.append(il.set_reg(4, "X", value))

        elif insn.bpf_class == BPF_ST:
            il.append(il.set_reg(4, f"M{insn.k}", il.reg(4, "A")))

        elif insn.bpf_class == BPF_STX:
            il.append(il.set_reg(4, f"M{insn.k}", il.reg(4, "X")))

        elif insn.bpf_class == BPF_ALU:
            if insn.bpf_aluop == BPF_NEG:
                value = il.neg_expr(4, il.reg(4, "A"))
            else:
                op_l = il.reg(4, "A")
                if insn.bpf_src == BPF_K:
                    op_r = il.const(4, insn.k)
                elif insn.bpf_src == BPF_X:
                    op_r = il.reg(4, "X")
                if insn.bpf_aluop == BPF_ADD:
                    value = il.add(4, op_l, op_r)
                elif insn.bpf_aluop == BPF_SUB:
                    value = il.sub(4, op_l, op_r)
                elif insn.bpf_aluop == BPF_MUL:
                    value = il.mult(4, op_l, op_r)
                elif insn.bpf_aluop == BPF_DIV:
                    value = il.div_unsigned(4, op_l, op_r)
                elif insn.bpf_aluop == BPF_AND:
                    value = il.and_expr(4, op_l, op_r)
                elif insn.bpf_aluop == BPF_OR:
                    value = il.or_expr(4, op_l, op_r)
                elif insn.bpf_aluop == BPF_LSH:
                    value = il.shift_left(4, op_l, op_r)
                elif insn.bpf_aluop == BPF_RSH:
                    value = il.logical_shift_right(4, op_l, op_r)
                elif insn.bpf_aluop == BPF_MOD:
                    value = il.mod_unsigned(4, op_l, op_r)
                elif insn.bpf_aluop == BPF_XOR:
                    value = il.xor_expr(4, op_l, op_r)
            il.append(il.set_reg(4, "A", value))

        elif insn.bpf_class == BPF_JMP:
            if insn.bpf_jmpop == BPF_JA:
                target = insn.jmp_target_ja(addr)
                label = il.x_label_for_address(target)
                il.append(il.goto(label))
            else:
                target_true, target_false = insn.jmp_target_jxx(addr)
                label_true = il.x_label_for_address(target_true)
                label_false = il.x_label_for_address(target_false)
                op_l = il.reg(4, "A")
                if insn.bpf_src == BPF_K:
                    op_r = il.const(4, insn.k)
                elif insn.bpf_src == BPF_X:
                    op_r = il.reg(4, "X")
                if insn.bpf_jmpop == BPF_JGT:
                    cond = il.compare_unsigned_greater_than(4, op_l, op_r)
                elif insn.bpf_jmpop == BPF_JGE:
                    cond = il.compare_unsigned_greater_equal(4, op_l, op_r)
                elif insn.bpf_jmpop == BPF_JEQ:
                    cond = il.compare_equal(4, op_l, op_r)
                elif insn.bpf_jmpop == BPF_JSET:
                    cond = il.compare_not_equal(4, il.const(4, 0), il.and_expr(4, op_l, op_r))
                #print(f" *** addr {addr:#06x} if_expr cond", cond, "labels", label_true, label_false, "targets", target_true, target_false)
                il.append(il.if_expr(cond, label_true, label_false))

        elif insn.bpf_class == BPF_RET:
            # The return value can be either in register A or in immediate k.
            # In the calling convention, we've arbitrarily designated register
            # A as the return value.  Hence, if the return value is already in
            # A, we're done and just need to emit the ret.  If the return value
            # is immediate value k, we need to emit an extra instruction that
            # sets A to k before returning.
            if insn.bpf_rval == BPF_A:
                pass
            elif insn.bpf_rval == BPF_K:
                il.append(il.set_reg(4, "A", il.const(4, insn.k)))
            il.append(il.ret(il.pop(4)))

        elif insn.bpf_class == BPF_MISC:
            if insn.bpf_miscop == BPF_TAX:
                il.append(il.set_reg(4, "X", il.reg(4, "A")))
            elif insn.bpf_miscop == BPF_TXA:
                il.append(il.set_reg(4, "A", il.reg(4, "X")))
            elif insn.bpf_miscop == BPF_COP:
                # XXX il.system_call() and appropriate calling convention
                il.append(il.unimplemented())
            elif insn.bpf_miscop == BPF_COPX:
                # XXX il.system_call() and appropriate calling convention
                il.append(il.unimplemented())

        return BPFInstruction.INSN_SIZE


class BPFLEArch(BPFArch):
    name = "bpf_le"
    endianness = binja.Endianness.LittleEndian


class BPFBEArch(BPFArch):
    name = "bpf_be"
    endianness = binja.Endianness.BigEndian


class BPFView(binja.BinaryView):
    @classmethod
    def is_valid_for_data(cls, data):
        """
        Raw BPF bytecode does not have any header, so we check that the buffer
        length is a multiple of the instruction length, and that every
        instruction is a valid instruction.  This is not ideal, but since
        length is bound by BPF_MAXINSNS, this seems workable.
        """
        if data.length > BPF_MAXINSNS * BPFInstruction.INSN_SIZE:
            return False
        if data.length % BPFInstruction.INSN_SIZE != 0:
            return False
        for offset in range(0, data.length, BPFInstruction.INSN_SIZE):
            buffer = data.read(offset, BPFInstruction.INSN_SIZE)
            try:
                insn = BPFInstruction(buffer, offset, cls.endianness)
            except BPFInstruction.InvalidInstructionError as e:
                return False
        return True

    def __init__(self, data):
        super().__init__(parent_view=data, file_metadata=data.file)
        self.platform = binja.Architecture[self.arch_cls.name].standalone_platform
        self.data = data

    def init(self):
        size = self.data.length
        self.add_auto_segment(0x0, size, 0, size,
                              binja.SegmentFlag.SegmentReadable
                              | binja.SegmentFlag.SegmentExecutable)
        self.add_user_section(".text", 0x0, size,
                              binja.SectionSemantics.ReadOnlyCodeSectionSemantics)
        self.add_entry_point(0x0)
        self.x_load_types(_TYPE_ID_SOURCE, _TYPE_SOURCE)
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return 0

    def perform_get_address_size(self):
        return 4


class BPFLEView(BPFView):
    name = "bpf_le"
    long_name = "Raw BPF LE"
    endianness = binja.Endianness.LittleEndian
    arch_cls = BPFLEArch


class BPFBEView(BPFView):
    name = "bpf_be"
    long_name = "Raw BPF BE"
    endianness = binja.Endianness.BigEndian
    arch_cls = BPFBEArch
