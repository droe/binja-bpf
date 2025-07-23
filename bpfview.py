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

from .bpfarch import BPFLEArch, BPFBEArch
from .bpfinsn import BPFInstruction, BPFLEInstruction, BPFBEInstruction
from .bpf import *


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

struct ip6_frag_hdr __packed {
    uint8_t     ip6f_nxt;
    uint8_t     ip6f_reserved;
    uint16_t    ip6f_offm;
    uint32_t    ip6f_id;
};

struct udp_hdr __packed {
    uint16_t    udp_sport;
    uint16_t    udp_dport;
    uint16_t    udp_len;
    uint16_t    udp_chksum;
};

struct tcp_hdr __packed {
    uint16_t    tcp_sport;
    uint16_t    tcp_dport;
    uint32_t    tcp_seq;
    uint32_t    tcp_ack;
    uint16_t    tcp_flags;
    uint16_t    tcp_win;
    uint16_t    tcp_chksum;
    uint16_t    tcp_urgptr;
};

struct sctp_chunk_hdr __packed {
    uint8_t     sctp_ctype;
    uint8_t     sctp_cflags;
    uint16_t    sctp_clen;
};

struct sctp_hdr __packed {
    uint16_t    sctp_sport;
    uint16_t    sctp_dport;
    uint32_t    sctp_vtag;
    uint32_t    sctp_chksum;
    struct sctp_chunk_hdr sctp_chunk[1];
};

struct icmp_hdr __packed {
    uint8_t     icmp_type;
    uint8_t     icmp_code;
    uint16_t    icmp_chksum;
};

union ipproto4 __packed {
    struct tcp_hdr      tcp;
    struct udp_hdr      udp;
    struct sctp_hdr     sctp;
    struct icmp_hdr     icmp;
};

union ipproto6 __packed {
    struct ip6_frag_hdr ip6f;
    struct tcp_hdr      tcp;
    struct udp_hdr      udp;
    struct sctp_hdr     sctp;
    struct icmp_hdr     icmp;
};

struct ip_packet __packed {
    union {
        struct {
            struct ip_hdr ip;
            union ipproto4 p;
        };
        struct {
            struct ip6_hdr ip6;
            union ipproto6 p6;
        };
    };
};

struct ether_packet __packed {
    struct eth_hdr eth;
    union {
        struct {
            struct ip_hdr ip;
            union ipproto4 p;
        };
        struct {
            struct ip6_hdr ip6;
            union ipproto6 p6;
        };
    };
};

enum ethertype_t {
    ETHERTYPE_IP            = 0x0800,
    ETHERTYPE_ARP           = 0x0806,
    ETHERTYPE_REVARP        = 0x8035,
    ETHERTYPE_8021Q         = 0x8100,
    ETHERTYPE_IPX           = 0x8137,
    ETHERTYPE_IPV6          = 0x86dd,
    ETHERTYPE_PPP           = 0x880b,
    ETHERTYPE_MPLS          = 0x8847,
    ETHERTYPE_MPLS_MULTI    = 0x8848,
    ETHERTYPE_JUMBO         = 0x8870,
    ETHERTYPE_EAPOL         = 0x888e,
    ETHERTYPE_CFM           = 0x8902,
    ETHERTYPE_LOOPBACK      = 0x9000,
};

enum ipproto_t {
    IPPROTO_ICMP        = 1,
    IPPROTO_TCP         = 6,
    IPPROTO_UDP         = 17,
    IPPROTO_IPV6FRAG    = 44,
    IPPROTO_ICMPV6      = 58,
    IPPROTO_SCTP        = 132,
};

enum ipv_t {
    IPV4    = 0x40,
    IPV6    = 0x60,
};

enum icmp_type_t {
    ICMP_ECHOREPLY          = 0,
    ICMP_UNREACH            = 3,
    ICMP_SOURCEQUENCH       = 4,
    ICMP_REDIRECT           = 5,
    ICMP_ALTHOSTADDR        = 6,
    ICMP_ECHO               = 8,
    ICMP_ROUTERADVERT       = 9,
    ICMP_ROUTERSOLICIT      = 10,
    ICMP_TIMXCEED           = 11,
    ICMP_PARAMPROB          = 12,
    ICMP_TSTAMP             = 13,
    ICMP_TSTAMPREPLY        = 14,
    ICMP_IREQ               = 15,
    ICMP_IREQREPLY          = 16,
    ICMP_MASKREQ            = 17,
    ICMP_MASKREPLY          = 18,
    ICMP_TRACEROUTE         = 30,
    ICMP_DATACONVERR        = 31,
    ICMP_MOBILE_REDIRECT    = 32,
    ICMP_IPV6_WHEREAREYOU   = 33,
    ICMP_IPV6_IAMHERE       = 34,
    ICMP_MOBILE_REGREQUEST  = 35,
    ICMP_MOBILE_REGREPLY    = 36,
    ICMP_SKIP               = 39,
    ICMP_PHOTURIS           = 40,
};
"""


class BPFView(binja.BinaryView):
    BASE_ADDR = 0x0

    @classmethod
    def is_valid_for_data(cls, data):
        # Raw BPF bytecode does not have any header, so we check that the buffer
        # length is a multiple of the instruction length, and that every
        # instruction is a valid instruction.  This is not ideal, but since
        # length is bound by BPF_MAXINSNS, this seems workable.
        if data.length > BPF_MAXINSNS * BPFInstruction.INSN_SIZE:
            return False
        if data.length % BPFInstruction.INSN_SIZE != 0:
            return False
        for offset in range(0, data.length, BPFInstruction.INSN_SIZE):
            buffer = data.read(offset, BPFInstruction.INSN_SIZE)
            try:
                insn = cls._insn_cls(buffer, offset)
            except BPFInstruction.DecodingError as e:
                return False
        return True

    def __init__(self, data):
        super().__init__(parent_view=data, file_metadata=data.file)
        self.platform = binja.Architecture[self._arch_cls.name].standalone_platform
        self.data = data

    def guess_packet_struct(self):
        """
        Guess the appropriate packet struct, i.e. whether the BPF program
        operates on Ethernet packets or IP packets, i.e. whether offset 0 of P
        is the start of an IPv4/IPv6 packet header or an Ethernet frame header.
        """
        for addr in range(self.BASE_ADDR, self.data.length, BPFInstruction.INSN_SIZE):
            insn_buffer = self.data.read(addr, BPFInstruction.INSN_SIZE)
            insn = self._insn_cls(insn_buffer, addr)
            # mov A, P[0xc:2]   ; load ether type
            if insn.code == BPF_LD + BPF_H + BPF_ABS and insn.k == 0xc:
                return "ether_packet"
            # mov A, P[0x0:1]   ; load IP version
            if insn.code == BPF_LD + BPF_B + BPF_ABS and insn.k == 0:
                return "ip_packet"
        return "ether_packet"

    def init(self):
        size = self.data.length
        self.add_auto_segment(self.BASE_ADDR, size,
                              self.BASE_ADDR, size,
                              binja.SegmentFlag.SegmentReadable
                              | binja.SegmentFlag.SegmentExecutable)
        self.add_user_section(".text", self.BASE_ADDR, size,
                              binja.SectionSemantics.ReadOnlyCodeSectionSemantics)
        self.add_entry_point(self.BASE_ADDR)
        self.x_load_types(_TYPE_ID_SOURCE, _TYPE_SOURCE)
        entry_point_func = self.get_function_at(self.BASE_ADDR)
        struct_name = self.guess_packet_struct()
        entry_point_func.type = f"uint32_t bpfmain(struct {struct_name} * __ptr32 P, uint32_t len)"
        return True

    def perform_is_executable(self):
        return True

    def perform_get_entry_point(self):
        return self.BASE_ADDR

    def perform_get_address_size(self):
        return 4


class BPFLEView(BPFView):
    name = "bpf_le"
    long_name = "Raw BPF LE"
    endianness = binja.Endianness.LittleEndian
    _insn_cls = BPFLEInstruction
    _arch_cls = BPFLEArch


class BPFBEView(BPFView):
    name = "bpf_be"
    long_name = "Raw BPF BE"
    endianness = binja.Endianness.BigEndian
    _insn_cls = BPFBEInstruction
    _arch_cls = BPFBEArch
