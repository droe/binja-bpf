# BPF Plugin
Author: Daniel Roethlisberger

Architecture plugin for the BPF virtual machine, and binary view for raw BPF
files.

## Description

Disassemble and decompile classic Berkeley Packet Filter (BPF) programs in
[Binary Ninja](https://binary.ninja/).

Currently supports classic BPF programs in their little and big endian macOS,
FreeBSD, NetBSD, OpenBSD and Linux flavours, including FreeBSD/Linux
`BPF_XOR`/`BPF_MOD`, OpenBSD `BPF_RND`, and limited support for NetBSD
`BPF_COP`/`BPF_COPX`.

Ships with convenient packet header structs, though for most BPF programs,
field offsets beyond the IP header will not resolve due to dynamic header
length calculations.

## Plans

The plugin should support loading libpcap cbpf-savefile(5) format binaries.

Support for extended BPF (eBPF) programs, raw binary eBPF programs, and eBPF
profile ELF files including BPF Type Format (BTF) would be a welcome addition
after classic BPF support stabilizes.  No plans for cryptocurrency virtual
machines based on eBPF.

## References

BPF ISA:

-   [BPF(4) manual page, FreeBSD](https://man.freebsd.org/cgi/man.cgi?bpf)
-   [BPF(4) manual page, NetBSD](https://man.netbsd.org/bpf.4)
-   [BPF(4) manual page, OpenBSD](https://man.openbsd.org/bpf.4)

eBPF ISA:

-   [RFC 9669: BPF Instruction Set Architecture (ISA)](https://www.rfc-editor.org/rfc/rfc9669.txt)
-   [Linux: BPF Instruction Set Architecture (ISA)](https://docs.kernel.org/bpf/standardization/instruction-set.html)

eBPF ELF:

-   [draft-thaler-bpf-elf-00](https://www.ietf.org/archive/id/draft-thaler-bpf-elf-00.html)

## License

This plugin is released under an [MIT license](./license).
