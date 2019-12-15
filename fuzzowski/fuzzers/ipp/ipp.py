from fuzzowski.fuzzers.ifuzzer import IFuzzer
from fuzzowski.mutants.spike import *
from fuzzowski import ITargetConnection, IFuzzLogger, Session, Request, RegexResponse

"""
     Value               Operation Name
     -----------------   -------------------------------------

     0x0000              reserved, not used
     0x0001              reserved, not used
     0x0002              Print-Job
     0x0003              Print-URI
     0x0004              Validate-Job
     0x0005              Create-Job
     0x0006              Send-Document
     0x0007              Send-URI
     0x0008              Cancel-Job
     0x0009              Get-Job-Attributes
     0x000A              Get-Jobs
     0x000B              Get-Printer-Attributes
     0x000C              Hold-Job
     0x000D              Release-Job
     0x000E              Restart-Job
     0x000F              reserved for a future operation
     0x0010              Pause-Printer
     0x0011              Resume-Printer
     0x0012              Purge-Jobs
     0x0013-0x3FFF       reserved for future IETF standards track
                         operations (see section 6.4)
     0x4000-0x8FFF       reserved for vendor extensions (see section 6.4)

"""


class IPP(IFuzzer):
    """IPP Fuzzer

    Define all LPD operations:
    Get Short Queue
    Get Long Queue
    Print Data File
    Remove Job
    """

    name = 'ipp'

    @staticmethod
    def get_requests() -> List[callable]:
        """Get possible requests"""
        return [IPP.http_headers, IPP.get_printer_attribs, IPP.print_uri_message, IPP.send_uri, IPP.get_jobs,
                IPP.get_job_attribs]

    @staticmethod
    def define_nodes(host: str = None, port: int = None, path: str = b'/', document_url: str = b'http://127.0.0.1/a.txt', *args, **kwargs) -> None:

        # ================================================================#
        # HTTP HEADERS                                                    #
        # ================================================================#

        # 1. Fuzzable Headers
        # Fuzz the HTTP headers and do a basic get printer attributes without fuzzing
        get_printer_attribs_message = (b"\x01\x01"  # version-number
                                       b"\x00\x0b"  # operation-id - Get-Printer-Attributes
                                       b"\x00\x01\xab\x10"  # request-id
                                       b"\x01"  # begin-attribute-group-tag

                                       b"\x47"  # value-tag - charset
                                       b"\x00\x12"  # name-length
                                       b"attributes-charset"  # name
                                       b"\x00\x05"  # value-length
                                       b"utf-8"  # value

                                       b"\x48"  # value-tag - natural language
                                       b"\x00\x1b"
                                       b"attributes-natural-language"
                                       b"\x00\x02"
                                       b"en"

                                       b"\x45"  # value-tag - uri
                                       b"\x00\x0b"
                                       b"printer-uri"
                                       b"\x00\x14"
                                       b"ipp://localhost/ipp/"

                                       b"\x44"  # value-tag - keyword
                                       b"\x00\x14"
                                       b"requested-attributes"
                                       b"\x00\x13"
                                       b"printer-description"
                                       b"\x03"  # end-of-attributes-tag
                                       )

        s_initialize("http_headers")
        s_string(b"POST", name='http_method')
        s_static(b" ")
        s_string(path, name='path')
        s_static(b" HTTP/1.0")
        s_static(b"\r\n")
        if host is not None:
            s_static(b"Host: ")
            s_string(host, name='host_header_hostname')
            if port is not None:
                s_delim(b':')
                s_string(str(port).encode(), name='host_header_port')
            s_static(b"\r\n")
        s_static(b"Accept-Encoding: ")
        s_string(b"identity", name='header_identity_encoding')
        s_static(b"\r\n")
        s_static(b"Content-Type: ")
        s_string(b"application/ipp", name='header_ipp_contenttype')
        s_static(b"\r\n")
        s_static(b"Connection: close\r\n")
        s_static(b"User-Agent: ")
        s_string(b"Fuzzowski Agent", name='user_agent')
        s_static(b"\r\n")
        with s_block('fuzz_header'):
            s_string(b'Fuzz-Header', name='header_name')
            s_delim(b':', name='header_separator')
            s_delim(b' ', name='header_separator_space')
            s_string(b"Fuzzowski", name='header_value')
            s_delim(b"\r\n", name='header_crlf')
        s_static(b"Content-Length: ")
        s_size("post_body", output_format="ascii", signed=True, fuzzable=True, name='Content-Length_size')
        s_static(b"\r\n")
        # s_repeat('fuzz_header', min_reps=0, max_reps=1000, step=100)
        s_delim(b"\r\n", name='crlf_headers_body')

        with s_block("post_body"):
            s_static(get_printer_attribs_message)
        # s_static(b"\r\n\r\n")

        # ================================================================#
        # GET_PRINTER_ATTRIBS                                             #
        # ================================================================#

        s_initialize("get_printer_attribs")
        s_static(f"POST {path} HTTP/1.1\r\n".encode())
        if host is not None:
            s_static(f"Host: {host}".encode())
            if port is not None:
                s_static(b':')
                s_static(str(port).encode())
            s_static(b"\r\n")
        s_static(b"Accept-Encoding: identity\r\n")
        s_static(b"Content-Type: application/ipp\r\n")
        s_static(b"Connection: close\r\n")
        s_static(b"User-Agent: Fuzzowski Agent\r\n")
        s_static(b"Content-Length: ")
        s_size("post_body", output_format="ascii", signed=True, fuzzable=False)
        s_static(b"\r\n\r\n")

        with s_block("post_body"):
            s_static(b"\x01\x01")  # version-number
            s_static(b"\x00\x0b")  # operation-id - Get-Printer-Attributes
            s_static(b"\x00\x01\xab\x10")  # request-id
            s_static(b"\x01")  # begin-attribute-group-tag

            s_static(b"\x47")  # value-tag - charset
            s_size("charset_p_name", output_format='binary', length=2, endian='>')  # name-length "\x00\x12"
            s_string(b"attributes-charset", name='charset_p_name')  # name
            s_size("charset_p_val", output_format='binary', length=2, endian='>')  # value-length "\x00\x05"
            s_string(b"utf-8", name='charset_p_val')  # value

            s_static(b"\x48")  # value-tag - natural language
            s_size("naturallang_p_name", output_format='binary', length=2, endian='>')  # name-length
            s_string(b"attributes-natural-language", name='naturallang_p_name')  # name
            s_size("naturallang_p_val", output_format='binary', length=2, endian='>')  # value-length
            s_string(b"en", name='naturallang_p_val')  # value

            s_static(b"\x45")  # value-tag - uri
            s_size("printeruri_p_name", output_format='binary', length=2, endian='>')  # name-length
            s_string(b"printer-uri", name='printeruri_p_name')  # name
            s_size("printeruri_p_val", output_format='binary', length=2, endian='>')  # value-length
            s_string(b"ipp://localhost/ipp/", name='printeruri_p_val')  # value

            s_static(b"\x44")  # value-tag - keyword
            s_size("keyword_p_name", output_format='binary', length=2, endian='>')  # name-length
            s_string(b"requested-attributes", name='keyword_p_name')  # name
            s_size("keyword_p_val", output_format='binary', length=2, endian='>')  # value-length
            s_string(b"printer-description", name='keyword_p_val')  # value

            s_static(b"\x03")  # end-of-attributes-tag

        # ================================================================#
        # PRINT_URI_MESSAGE                                               #
        # ================================================================#

        s_initialize("print_uri_message")
        s_static("POST {} HTTP/1.1\r\n".format(path).encode())
        if host is not None:
            s_static("Host: {}".format(host).encode())
            if port is not None:
                s_static(b':')
                s_static(str(port).encode())
            s_static(b"\r\n")
        s_static(b"Accept-Encoding: identity\r\n")
        s_static(b"Content-Type: application/ipp\r\n")
        s_static(b"Connection: close\r\n")
        s_static(b"User-Agent: Fuzzowski Agent\r\n")
        s_static(b"Content-Length: ")
        s_size("post_body", output_format="ascii", signed=True, fuzzable=False)
        s_static(b"\r\n\r\n")
        with s_block("post_body"):
            s_static(b"\x01\x01")  # version-number
            s_static(b"\x00\x03")  # operation-id - Print-URI
            s_static(b"\x00\x00\x00\x01")  # request-id
            s_static(b"\x01")  # begin-attribute-group-tag

            s_static(b"\x47")  # value-tag - charset
            s_size("charset_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"attributes-charset", name='charset_p_name', fuzzable=False)  # name
            s_size("charset_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"utf-8", name='charset_p_val', fuzzable=False)  # value

            s_static(b"\x48")  # value-tag - natural language
            s_size("naturallang_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"attributes-natural-language", name='naturallang_p_name', fuzzable=False)  # name
            s_size("naturallang_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"en-us", name='naturallang_p_val', fuzzable=False)  # value

            s_static(b"\x45")  # value-tag - uri
            s_size("printeruri_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"printer-uri", name='printeruri_p_name', fuzzable=False)  # name
            s_size("printeruri_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"ipp://localhost/ipp/", name='printeruri_p_val', fuzzable=False)  # value

            s_static(b"\x45")  # value-tag - uri
            s_size("documenturi_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"document-uri", name='documenturi_p_name', fuzzable=False)  # name - Fuzzable!
            s_size("documenturi_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(document_url, name='documenturi_p_val', fuzzable=True)  # value

            s_static(b"\x42")  # value-tag - job?
            s_size("jobname_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"job-name", name='jobname_p_name', fuzzable=False)  # name
            s_size("jobname_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"Fuzzowski_Job", name='jobname_p_val', fuzzable=False)  # value

            s_static(b"\x02")  # begin-control-attribute-group-tag

            s_static(b"\x21")  # value-tag - copies??
            s_size("copies_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"copies", name='copies_p_name', fuzzable=False)  # name
            s_size("copies_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b'\x00\x00\x00\x01', name='copies_p_val', fuzzable=False)  # value

            s_static(b"\x03")  # end-of-attributes-tag

        # ================================================================#
        # CREATE_JOB                                                      #
        # ================================================================#

        s_initialize("create_job")
        s_static(f"POST {path} HTTP/1.1\r\n".encode())
        if host is not None:
            s_static(f"Host: {host}".encode())
            if port is not None:
                s_static(b':')
                s_static(str(port).encode())
            s_static(b"\r\n")
        s_static(b"Accept-Encoding: identity\r\n")
        s_static(b"Content-Type: application/ipp\r\n")
        s_static(b"Connection: close\r\n")
        s_static(b"User-Agent: Fuzzowski Agent\r\n")
        s_static(b"Content-Length: ")
        s_size("post_body", output_format="ascii", signed=True, fuzzable=False)
        s_static(b"\r\n\r\n")
        with s_block("post_body"):
            s_static(b'\x02\x00')  # version-number
            s_static(b'\x00\x05')  # operation-id - Create-Job
            s_static(b'\x00\x00\x00\x04')  # request-id
            s_static(b'\x01')  # begin-attribute-group-tag

            s_static(b"\x47")  # value-tag - charset
            s_size("charset_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"attributes-charset", name='charset_p_name', fuzzable=False)  # name
            s_size("charset_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"utf-8", name='charset_p_val', fuzzable=False)  # value

            s_static(b"\x48")  # value-tag - natural language
            s_size("naturallang_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"attributes-natural-language", name='naturallang_p_name', fuzzable=False)  # name
            s_size("naturallang_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"en-us", name='naturallang_p_val', fuzzable=False)  # value

            s_static(b"\x45")  # value-tag - uri
            s_size("printeruri_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"printer-uri", name='printeruri_p_name', fuzzable=False)  # name
            s_size("printeruri_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"ipp://localhost/ipp/", name='printeruri_p_val', fuzzable=False)  # value

            s_static(b"\x42")  # value-tag - ??
            s_size("username_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"requesting-user-name", name='username_p_name', fuzzable=False)  # name
            s_size("username_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"root", name='username_p_val', fuzzable=False)  # value

            s_static(b"\x42")  # value-tag - job?
            s_size("jobname_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"job-name", name='jobname_p_name', fuzzable=False)  # name
            s_size("jobname_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"Fuzzowski_Job", name='jobname_p_val', fuzzable=True)  # value

            s_static(b'\x02')

            s_static(b"\x44")  # value-tag
            s_size("sides_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"sides", name='sides_p_name', fuzzable=False)  # name
            s_size("sides_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b'one-sided', name='sides_p_val', fuzzable=False)  # value

            s_static(b"\x44")  # value-tag
            s_size("dochandling_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"multiple-document-handling", name='dochandling_p_name', fuzzable=False)  # name
            s_size("dochandling_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b'separate-documents-uncollated-copies', name='dochandling_p_val', fuzzable=False)  # value

            s_static(b'\x03')

        # Declare Response to extract job-id!
        s_response(RegexResponse, name='create_job_response', required_vars=['jobid_p_val'], optional_vars=[],
                   regex_list=[b'job-id.{2}(?P<jobid_p_val>.{4})'])

        # ================================================================#
        # SEND_URI                                                        #
        # ================================================================#

        s_initialize("send_uri")
        s_static(f"POST {path} HTTP/1.1\r\n".encode())
        if host is not None:
            s_static(f"Host: {host}".encode())
            if port is not None:
                s_static(b':')
                s_static(str(port).encode())
            s_static(b"\r\n")
        s_static(b"Accept-Encoding: identity\r\n")
        s_static(b"Content-Type: application/ipp\r\n")
        s_static(b"Connection: close\r\n")
        s_static(b"User-Agent: Fuzzowski Agent\r\n")
        s_static(b"Content-Length: ")
        s_size("post_body", output_format="ascii", signed=True, fuzzable=False)
        s_static(b"\r\n\r\n")
        with s_block("post_body"):
            s_static(b'\x02\x00')  # version-number
            s_static(b'\x00\x07')  # operation-id - Send-URI
            s_static(b'\x00\x00\x00\x05')  # request-id
            s_static(b'\x01')  # begin-attribute-group-tag

            s_static(b"\x47")  # value-tag - charset
            s_size("charset_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"attributes-charset", name='charset_p_name', fuzzable=False)  # name
            s_size("charset_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"utf-8", name='charset_p_val', fuzzable=False)  # value

            s_static(b"\x48")  # value-tag - natural language
            s_size("naturallang_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"attributes-natural-language", name='naturallang_p_name', fuzzable=False)  # name
            s_size("naturallang_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"en-us", name='naturallang_p_val', fuzzable=False)  # value

            s_static(b"\x45")  # value-tag - uri
            s_size("printeruri_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"printer-uri", name='printeruri_p_name', fuzzable=False)  # name
            s_size("printeruri_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"ipp://localhost/ipp/", name='printeruri_p_val', fuzzable=False)  # value

            s_static(b"\x21")  # value-tag - jobid?
            s_size("jobid_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"job-id", name='jobid_p_name', fuzzable=False)  # name
            s_size("jobid_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            # s_string(b"\x00\x00\x00\x02", name='jobid_p_val', fuzzable=False)  # job-id, will be changed by callback
            s_variable('jobid_p_val', b'\x00\x00\x01\xe4', fuzzable=False)  # job-id, will be set by create_job response


            s_static(b"\x42")  # value-tag - ??
            s_size("username_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"requesting-user-name", name='username_p_name', fuzzable=False)  # name
            s_size("username_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"root", name='username_p_val', fuzzable=False)  # value

            s_static(b"\x22")  # value-tag - ??
            s_size("lastdocument_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"last-document", name='lastdocument_p_name', fuzzable=False)  # name
            s_size("lastdocument_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"\x01", name='lastdocument_p_val', fuzzable=False)  # value

            s_static(b"\x45")  # value-tag - uri
            s_size("documenturi_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"document-uri", name='documenturi_p_name', fuzzable=False)  # name - Fuzzable!
            s_size("documenturi_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(document_url, name='documenturi_p_val', fuzzable=True)  # value

            s_static(b'\x03')

        # ================================================================#
        # GET_JOBS                                                        #
        # ================================================================#

        s_initialize("get_jobs")
        s_static(f"POST {path} HTTP/1.1\r\n".encode())
        if host is not None:
            s_static(f"Host: {host}".encode())
            if port is not None:
                s_static(b':')
                s_static(str(port).encode())
            s_static(b"\r\n")
        s_static(b"Accept-Encoding: identity\r\n")
        s_static(b"Content-Type: application/ipp\r\n")
        s_static(b"Connection: close\r\n")
        s_static(b"User-Agent: Fuzzowski Agent\r\n")
        s_static(b"Content-Length: ")
        s_size("post_body", output_format="ascii", signed=True, fuzzable=False)
        s_static(b"\r\n\r\n")
        with s_block("post_body"):
            s_static(b'\x02\x00')  # version-number
            s_static(b'\x00\x0A')  # operation-id - Get-Jobs
            s_static(b'\x00\x00\x00\x05')  # request-id
            s_static(b'\x01')  # begin-attribute-group-tag

            s_static(b"\x47")  # value-tag - charset
            s_size("charset_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"attributes-charset", name='charset_p_name', fuzzable=False)  # name
            s_size("charset_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"utf-8", name='charset_p_val', fuzzable=False)  # value

            s_static(b"\x48")  # value-tag - natural language
            s_size("naturallang_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"attributes-natural-language", name='naturallang_p_name', fuzzable=False)  # name
            s_size("naturallang_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"en-us", name='naturallang_p_val', fuzzable=False)  # value

            s_static(b"\x45")  # value-tag - uri
            s_size("printeruri_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"printer-uri", name='printeruri_p_name', fuzzable=False)  # name
            s_size("printeruri_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"ipp://localhost/ipp/", name='printeruri_p_val', fuzzable=False)  # value

            s_static(b"\x21")  # value-tag - number?
            s_size("limit_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"limit", name='limit_p_name', fuzzable=False)  # name
            s_size("limit_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"\x00\x00\x00\x32", name='limit_p_val', fuzzable=False)  #

            s_static(b"\x44")  # value-tag
            s_size("reqattribs_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"requested-attributes", name='reqattribs_p_name', fuzzable=False)  # name
            s_size("reqattribs_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"job-id", name='reqattribs_p_val', fuzzable=False)
            s_static(b"\x44")  # value-tag
            s_static(b"\x00\x00")  # no name
            s_size("reqattrib2_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"job-name", name='reqattrib2_p_val', fuzzable=False)

            with s_block('reqattrib3'):
                s_static(b"\x44")  # value-tag
                s_static(b"\x00\x00")  # no name
                s_size("reqattrib3_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
                s_string(b"document-format", name='reqattrib3_p_val', fuzzable=True)
            s_repeat('reqattrib3', name='repeat_reqattr', min_reps=0, max_reps=1000, step=100)

            s_static(b'\x03')

        # ================================================================#
        # GET_JOB_ATTRIBS                                                 #
        # ================================================================#

        s_initialize("get_job_attribs")
        s_static(f"POST {path} HTTP/1.1\r\n".encode())
        if host is not None:
            s_static(f"Host: {host}".encode())
            if port is not None:
                s_static(b':')
                s_static(str(port).encode())
            s_static(b"\r\n")
        s_static(b"Accept-Encoding: identity\r\n")
        s_static(b"Content-Type: application/ipp\r\n")
        s_static(b"Connection: close\r\n")
        s_static(b"User-Agent: Fuzzowski Agent\r\n")
        s_static(b"Content-Length: ")
        s_size("post_body", output_format="ascii", signed=True, fuzzable=False)
        s_static(b"\r\n\r\n")
        with s_block("post_body"):
            s_static(b"\x01\x01")  # version-number
            s_static(b"\x00\x09")  # operation-id - Get-Job-Attributes
            s_static(b"\x00\x01\xab\x10")  # request-id
            s_static(b"\x01")  # begin-attribute-group-tag

            s_static(b"\x47")  # value-tag - charset
            s_size("charset_p_name", output_format='binary', length=2, endian='>')  # name-length "\x00\x12"
            s_string(b"attributes-charset", name='charset_p_name')  # name
            s_size("charset_p_val", output_format='binary', length=2, endian='>')  # value-length "\x00\x05"
            s_string(b"utf-8", name='charset_p_val')  # value

            s_static(b"\x48")  # value-tag - natural language
            s_size("naturallang_p_name", output_format='binary', length=2, endian='>')  # name-length
            s_string(b"attributes-natural-language", name='naturallang_p_name')  # name
            s_size("naturallang_p_val", output_format='binary', length=2, endian='>')  # value-length
            s_string(b"en-gb", name='naturallang_p_val')  # value

            # s_static(b"\x45")  # value-tag - uri
            # s_size("joburi_p_name", output_format='binary', length=2, endian='>')  # name-length
            # s_string(b"job-uri", name='joburi_p_name')  # name
            # s_size("joburi_p_val", output_format='binary', length=2, endian='>')  # value-length
            # s_string(b"ipp://printer:631/print/job396", name='joburi_p_val')  # value

            s_static(b"\x45")  # value-tag - uri
            s_size("printeruri_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"printer-uri", name='printeruri_p_name', fuzzable=False)  # name
            s_size("printeruri_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"ipp://localhost/ipp/", name='printeruri_p_val', fuzzable=False)  # value

            s_static(b"\x21")  # value-tag - jobid?
            s_size("jobid_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"job-id", name='jobid_p_name', fuzzable=False)  # name
            s_size("jobid_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            # s_string(b"\x00\x00\x01\xe4", name='jobid_p_val', fuzzable=False)  # job-id, will be changed by callback
            s_variable('jobid_p_val', b'\x00\x00\x01\xe4', fuzzable=False)  # job-id, will be changed by callback

            s_static(b"\x42")  # value-tag - ??
            s_size("username_p_name", output_format='binary', length=2, endian='>', fuzzable=False)  # name-length
            s_string(b"requesting-user-name", name='username_p_name', fuzzable=False)  # name
            s_size("username_p_val", output_format='binary', length=2, endian='>', fuzzable=False)  # value-length
            s_string(b"root", name='username_p_val', fuzzable=False)  # value

            s_static(b"\x44")  # value-tag - keyword
            s_size("keyword_p_name", output_format='binary', length=2, endian='>')  # name-length
            s_string(b"requested-attributes", name='keyword_p_name')  # name
            s_size("keyword_p_val", output_format='binary', length=2, endian='>')  # value-length
            s_string(b"all", name='keyword_p_val')  # value

            s_static(b"\x03")  # end-of-attributes-tag

            # b'\x02\x00' \
            # b'\x00\t' \
            # b'\x00\x00\x00\xf3' \
            # b'\x01' \
            # b'G\x00\x12attributes-charset\x00\x05utf-8' \
            # b'H\x00\x1battributes-natural-language\x00\x05en-gb' \
            # b'E\x00\x0bprinter-uri\x00(ipp://printer:631/ipp/print' \
            # b'!\x00\x06job-id\x00\x04\x00\x00\x01\xde' \
            # b'B\x00\x14requesting-user-name\x00\x05mario' \
            # b'D\x00\x14requested-attributes\x00\x06job-idD\x00\x00\x00\x19job-impressions-completedD\x00\x00\x00\x1ajob-media-sheets-completedD\x00\x00\x00\x08job-nameD\x00\x00\x00\x19job-originating-user-nameD\x00\x00\x00\tjob-stateD\x00\x00\x00\x11job-state-reasons' \
            # b'\x03'


    @staticmethod
    def http_headers(session: Session) -> None:
        session.connect(s_get('http_headers'))

    @staticmethod
    def get_printer_attribs(session: Session) -> None:
        session.connect(s_get('get_printer_attribs'))

    @staticmethod
    def print_uri_message(session: Session) -> None:
        session.connect(s_get('print_uri_message'))

    # --------------------------------------------------------------- #

    @staticmethod
    def cb_set_jobid(target: ITargetConnection, logger: IFuzzLogger, session: Session, node: Request,
                     edge, original: bool, *args, **kwargs) -> bytes:
        """
        Callback used in send_uri that obtains the job-id and sets it in the send_uri node

        :param target: Target
        :param logger: Logger
        :param session: Fuzzing Session, most useful is session.last_recv
        :param node: Node to render next
        :param edge:
        :param args:
        :param kwargs:
        :return: the data of node.render() replacing the job-id for the one received in session.last_recv
        """
        logger.log_info('Callback set_job_id')
        # target.close()
        # target.open()
        job_id = session.last_recv[session.last_recv.find(b'job-id'):][8:][0:4]  # Extract job-id
        job_id_int = int.from_bytes(job_id, byteorder='big')

        logger.log_info('job-id found: {} = {}'.format(job_id, job_id_int))

        data = node.render(replace_node='jobid_p_val', replace_value=job_id, original=original)
        # logger.log_info(data)
        #return None
        return data

    @staticmethod
    def send_uri(session: Session) -> None:
        session.connect(s_get('create_job'))
        session.connect(s_get('create_job'), s_get('send_uri'))
        # session.connect(s_get('create_job'), s_get('send_uri'), callback=IPP.cb_set_jobid)

    # --------------------------------------------------------------- #

    @staticmethod
    def get_jobs(session: Session) -> None:
        session.connect(s_get('create_job'))
        session.connect(s_get('create_job'), s_get('get_jobs'))

    @staticmethod
    def get_job_attribs(session: Session) -> None:
        session.connect(s_get('create_job'))
        session.connect(s_get('create_job'), s_get('get_job_attribs'))
        # session.connect(s_get('create_job'), s_get('get_job_attribs'), callback=IPP.cb_set_jobid)




