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

    def insn(self, code, jt, jf, k):
        self._insns.append(struct.pack(self._insn_layout, code, jt, jf, k))

    def BPF_STMT(self, opcode, operand):
        self.insn(opcode, 0, 0, operand)

    def BPF_JUMP(self, opcode, operand, true_offset, false_offset):
        self.insn(opcode, true_offset, false_offset, operand)

    def __bytes__(self):
        return b''.join(self._insns)

    def write_to(self, path):
        with open(path, "wb") as f:
            f.write(bytes(self))

    @classmethod
    def build_examples(cls, prefix):
        """
        Writes a number of BPF filter examples to path.
        """

        # Classic reverse ARP example from BSD manual pages
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
        c.write_to(f"{prefix}rarp.bpfcode")

        # Classic IP address pair example from BSD manual pages
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
        c.write_to(f"{prefix}ipaddr.bpfcode")

        # Classic TCP finger example from BSD manual pages
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
        c.write_to(f"{prefix}tcpfinger.bpfcode")

        # OpenBSD specific instructions
        c = cls()
        c.BPF_STMT(BPF_LD+BPF_W+BPF_RND, 0)
        c.BPF_STMT(BPF_RET+BPF_A, 0)
        c.write_to(f"{prefix}openbsd.bpfcode")

        # FreeBSD/Linux specific instructions
        c = cls()
        c.BPF_STMT(BPF_LD+BPF_IMM, 1337)
        c.BPF_STMT(BPF_LDX+BPF_W+BPF_IMM, 1)
        c.BPF_STMT(BPF_ALU+BPF_MOD+BPF_K, 13)
        c.BPF_STMT(BPF_ALU+BPF_MOD+BPF_X, 0)
        c.BPF_STMT(BPF_ALU+BPF_XOR+BPF_K, 0xBFBFBFBF)
        c.BPF_STMT(BPF_ALU+BPF_XOR+BPF_X, 0)
        c.BPF_STMT(BPF_RET+BPF_A, 0)
        c.write_to(f"{prefix}freebsd.bpfcode")

        # bpfdoor as per https://raw.githubusercontent.com/snapattack/bpfdoor-scanner/refs/heads/main/sample/bpfdoor.c
        c = cls()
        lines = """
                { 0x28, 0, 0, 0x0000000c },
                { 0x15, 0, 27, 0x00000800 },
                { 0x30, 0, 0, 0x00000017 },
                { 0x15, 0, 5, 0x00000011 },
                { 0x28, 0, 0, 0x00000014 },
                { 0x45, 23, 0, 0x00001fff },
                { 0xb1, 0, 0, 0x0000000e },
                { 0x48, 0, 0, 0x00000016 },
                { 0x15, 19, 20, 0x00007255 },
                { 0x15, 0, 7, 0x00000001 },
                { 0x28, 0, 0, 0x00000014 },
                { 0x45, 17, 0, 0x00001fff },
                { 0xb1, 0, 0, 0x0000000e },
                { 0x48, 0, 0, 0x00000016 },
                { 0x15, 0, 14, 0x00007255 },
                { 0x50, 0, 0, 0x0000000e },
                { 0x15, 11, 12, 0x00000008 },
                { 0x15, 0, 11, 0x00000006 },
                { 0x28, 0, 0, 0x00000014 },
                { 0x45, 9, 0, 0x00001fff },
                { 0xb1, 0, 0, 0x0000000e },
                { 0x50, 0, 0, 0x0000001a },
                { 0x54, 0, 0, 0x000000f0 },
                { 0x74, 0, 0, 0x00000002 },
                { 0xc, 0, 0, 0x00000000 },
                { 0x7, 0, 0, 0x00000000 },
                { 0x48, 0, 0, 0x0000000e },
                { 0x15, 0, 1, 0x00005293 },
                { 0x6, 0, 0, 0x0000ffff },
                { 0x6, 0, 0, 0x00000000 },
        """.strip().splitlines()
        for line in lines:
            for rmc in ("{", ",", "}"):
                line = line.replace(rmc, "")
            ints = [int(x, 0) for x in line.strip().split()]
            c.insn(*ints)
        c.write_to(f"{prefix}bpfdoor.bpfcode")

class BPFLECompiler(BPFCompiler):
    _insn_layout = '<HBBI'


class BPFBECompiler(BPFCompiler):
    _insn_layout = '>HBBI'


if __name__ == '__main__':
    BPFLECompiler.build_examples("./examples/bpf_le/example_")
    BPFBECompiler.build_examples("./examples/bpf_be/example_")
