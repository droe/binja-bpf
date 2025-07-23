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


import struct

from .bpf import *


class BPFInstruction:
    """
    Abstract base class for decoding a BPF instruction.
    """

    class DecodingError(Exception):
        pass

    class InvalidStorageError(DecodingError):
        pass

    class InvalidInstructionError(DecodingError):
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

    def __init__(self, data, addr):
        if (addr % BPFInstruction.INSN_SIZE) != 0:
            raise BPFInstruction.InvalidStorageError(f"Misaligned address {addr:#06x}")
        if len(data) < BPFInstruction.INSN_SIZE:
            raise BPFInstruction.InvalidStorageError(f"Buffer smaller than min insn length")

        self.code, self.jt, self.jf, self.k = struct.unpack(self._insn_layout, data[:BPFInstruction.INSN_SIZE])

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


class BPFLEInstruction(BPFInstruction):
    """
    Decoder for little-endian BPF instructions.
    """
    _insn_layout = '<HBBI'


class BPFBEInstruction(BPFInstruction):
    """
    Decoder for little-endian BPF instructions.
    """
    _insn_layout = '>HBBI'
