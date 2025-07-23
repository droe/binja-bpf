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
