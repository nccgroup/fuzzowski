from typing import List

from fuzzowski.fuzzers import IFuzzer
from fuzzowski import Session
from fuzzowski.mutants.spike import *
import base64


class DNSClient(IFuzzer):
    """DNS Client Fuzzer
    """

    name = 'dns_client'

    @staticmethod
    def get_requests() -> List[callable]:
        """Get possible requests"""
        return [DNSClient.response]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:

        resp = (

            b'\x06\x00'  # transaction_id
            b'\x81\x80'  # Flags
            b'\x00\x01'  # questions (1)
            b'\x00\x02'  # answer RRs (2)
            b'\x00\x00'  # Authority RRs (0)
            b'\x00\x00'  # Additional RRs (0)
            # queries
            b'\x03'  # size
            b'www'
            b'\x08'  # size
            b'nccgroup'
            b'\x05'  # size
            b'trust'
            b'\x00'  # end_delim
            b'\x00\x01'  # type (A)
            b'\x00\x01'  # class (IN)
            # answers
            b'\xc0\x0c'  # ???
            b'\x00\x05'  # type (CNAME)
            b'\x00\x01'  # class (IN)
            b'\x00\x00\x00\x7f'  # ttl (127)
            b'\x00\x16'  # data length (22)
            
            b'\x05'
            b'j9ant'
            b'\x01'
            b'x'
            b'\x08'
            b'incapdns'
            b'\x03'
            b'net'
            b'\x00'
        
            b'\xc0\x30'  # ???
            b'\x00\x01'  # type (A)
            b'\x00\x01'  # class (IN)
            b'\x00\x00\x00\x1d'  # ttl (29)
            
            b'\x00\x04'  # data length (4)
            b'\x95\x7e\x4a\x67'  # IP address (149.126.74.103)
        )

        s_initialize('response')
        s_word(b'\x06\x00', name='transaction_id')  # transaction_id
        s_word(b'\x81\x80', name='flags')  # Flags
        s_word(b'\x00\x01', name='questions')  # questions (1)
        s_word(b'\x00\x02', name='rrs')  # answer RRs (2)
        s_word(b'\x00\x00', name='authority_rrs')  # Authority RRs (0)
        s_word(b'\x00\x00', name='additional_rrs')  # Additional RRs (0)
        # queries
        s_size("qname_1", output_format="binary", length=1, signed=True, fuzzable=True, name='name_1_size')  # b'\x03'
        s_string(b'www', name='qname_1')
        s_size("qname_2", output_format="binary", length=1, signed=True, fuzzable=True, name='name_2_size')  # b'\x08'
        s_string(b'nccgroup', name='qname_2')
        s_size("qname_3", output_format="binary", length=1, signed=True, fuzzable=True, name='name_3_size')  # b'\x05'
        s_string(b'trust', name='qname_3')
        s_delim(b'\x00', name='qname_end')  # end_delim
        s_word(b'\x00\x01', name='query_type')  # type (A)
        s_word(b'\x00\x01', name='query_class')  # class (IN)
        # answers
        s_word(b'\xc0\x0c')  # ???
        s_word(b'\x00\x05', name='a_type')  # type (CNAME)
        s_word(b'\x00\x01', name='a_class')  # class (IN)
        s_dword(b'\x00\x00\x00\x01', name='ttl')  # ttl (1)

        s_size("answer", output_format="binary", length=2, name='answer_size') # b'\x00\x16' data length (22)
        with s_block("answer"):
            s_size("aname_1", output_format="binary", length=1, name='aname_1_size')  # b'\x03'
            s_string(b'j9ant', name='aname_1')
            s_size("aname_2", output_format="binary", length=1, name='aname_2_size')  # b'\x08'
            s_string(b'x', name='aname_2')
            s_size("aname_3", output_format="binary", length=1, name='aname_3_size')  # b'\x05'
            s_string(b'incapdns', name='aname_3')
            s_size("aname_4", output_format="binary", length=1, name='aname_4_size')  # b'\x05'
            s_string(b'net', name='aname_4')
            s_delim(b'\x00', name='aname_end')  # end_delim

        s_word(b'\xc0\x30')  # ???
        s_word(b'\x00\x01', name='a2_type')  # type (A)
        s_word(b'\x00\x01', name='a2_class')  # class (IN)
        s_dword(b'\x00\x00\x00\x1d', name='a_ttl')  # ttl (29)

        s_size("ip", output_format="binary", length=2, name='ip_size')  # b'\x00\x04'  # data length (4)
        s_string(b'\x95\x7e\x4a\x67', name='ip')  # IP address (149.126.74.103) (maybe a dword of 4 bytes?)

        # --------------------------------------------------------------- #

    @staticmethod
    def response(session: Session) -> None:
        session.connect(s_get('response'))
