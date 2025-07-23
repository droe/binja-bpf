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

from .bpfinsn import BPFInstruction, BPFLEInstruction, BPFBEInstruction
from .bpf import *


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

    intrinsics = {
        'arc4random': binja.IntrinsicInfo([binja.Type.int(4)], []),
    }

    def get_instruction_info(self, data, addr):
        try:
            insn = self._insn_cls(data, addr)
        except BPFInstruction.InvalidStorageError as e:
            return None

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
            insn = self._insn_cls(data, addr)
        except BPFInstruction.InvalidStorageError as e:
            return [], 0

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
        # Workaround for https://github.com/Vector35/binaryninja-api/issues/7099
        # Spurious calls for single addresses have len(il) == 0.
        # Because BPF only every has a single function, always mapped at offset 0,
        # len(il) == 0 can only happen legitimately for addr == 0.
        # This workaround does not cover spurious calls for addr == 0.  That
        # seems acceptable, as we have not seen any spurious calls for offset 0.
        if addr != 0 and len(il) == 0:
            return 0

        try:
            insn = self._insn_cls(data, addr)
        except BPFInstruction.InvalidStorageError as e:
            return 0

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
    _insn_cls = BPFLEInstruction


class BPFBEArch(BPFArch):
    name = "bpf_be"
    endianness = binja.Endianness.BigEndian
    _insn_cls = BPFBEInstruction


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
