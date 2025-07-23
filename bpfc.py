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

if __package__ is None or __package__ == '':
    from bpf import *
else:
    from .bpf import *


class BPFCompiler:
    """
    Abstract base class for BPF compilers to assist in testing.

    Designed to make conversion from the C form as direct as possible.
    """
    def __init__(self):
        self._insns = []

    def _insn(self, code, jt, jf, k):
        self._insns.append(struct.pack(self._insn_layout, code, jt, jf, k))

    def BPF_STMT(self, opcode, operand):
        self._insn(opcode, 0, 0, operand)

    def BPF_JUMP(self, opcode, operand, true_offset, false_offset):
        self._insn(opcode, true_offset, false_offset, operand)

    def __bytes__(self):
        return b''.join(self._insns)

    @classmethod
    def build_examples(cls, prefix):
        """
        Writes the classic BPF filter examples given in the BSD manual pages to
        path.
        """
        ETHERTYPE_REVARP = 0x8035
        REVARP_REQUEST = 3
        SIZEOF_ETHER_ARP = 28
        SIZEOF_ETHER_HEADER = 14
        c = cls()
        c.BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_REVARP, 0, 3)
        c.BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 20)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, REVARP_REQUEST, 0, 1)
        c.BPF_STMT(BPF_RET+BPF_K, SIZEOF_ETHER_ARP + SIZEOF_ETHER_HEADER)
        c.BPF_STMT(BPF_RET+BPF_K, 0)
        with open(f"{prefix}rarp.bpfcode", "wb") as f:
            f.write(bytes(c))

        ETHERTYPE_IP = 0x0800
        c = cls()
        c.BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 8)
        c.BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 26)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 2)
        c.BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 3, 4)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x80037023, 0, 3)
        c.BPF_STMT(BPF_LD+BPF_W+BPF_ABS, 30)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 0x8003700f, 0, 1)
        c.BPF_STMT(BPF_RET+BPF_K, 0xFFFFFFFF)
        c.BPF_STMT(BPF_RET+BPF_K, 0)
        with open(f"{prefix}ipaddr.bpfcode", "wb") as f:
            f.write(bytes(c))

        ETHERTYPE_IP = 0x0800
        IPPROTO_TCP = 6
        c = cls()
        c.BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 12)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, ETHERTYPE_IP, 0, 10)
        c.BPF_STMT(BPF_LD+BPF_B+BPF_ABS, 23)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, IPPROTO_TCP, 0, 8)
        c.BPF_STMT(BPF_LD+BPF_H+BPF_ABS, 20)
        c.BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, 0x1fff, 6, 0)
        c.BPF_STMT(BPF_LDX+BPF_B+BPF_MSH, 14)
        c.BPF_STMT(BPF_LD+BPF_H+BPF_IND, 14)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 79, 2, 0)
        c.BPF_STMT(BPF_LD+BPF_H+BPF_IND, 16)
        c.BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, 79, 0, 1)
        c.BPF_STMT(BPF_RET+BPF_K, 0xFFFFFFFF)
        c.BPF_STMT(BPF_RET+BPF_K, 0)
        with open(f"{prefix}tcpfinger.bpfcode", "wb") as f:
            f.write(bytes(c))


class BPFLECompiler(BPFCompiler):
    _insn_layout = '<HBBI'


class BPFBECompiler(BPFCompiler):
    _insn_layout = '>HBBI'


if __name__ == '__main__':
    BPFLECompiler.build_examples("./examples/bpf_le/example_")
    BPFBECompiler.build_examples("./examples/bpf_be/example_")
