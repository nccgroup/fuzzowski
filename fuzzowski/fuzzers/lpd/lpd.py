from fuzzowski.fuzzers.ifuzzer import IFuzzer
from fuzzowski.mutants.spike import *
from fuzzowski import Session

CTRL_FILE_OPTIONS = [
    "C",  # 7.1 C - Class for Banner Page - Name of class for banner pages
    "H",  # 7.2 H - Host name - hostname
    "I",  # 7.3 I - Indent Printing - Indenting Count
    "J",  # 7.4 J - Job name for banner page - Job name
    "L",  # 7.5 L - Print banner page - Name of user for burst pages
    "M",  # 7.6 M - Mail when printed - User
    "N",  # 7.7 N - Name of source file - File name (to specify file to print with p)
    "P",  # 7.8 P - User identification - User id (31 octets max)
    "S",  # 7.9 S - Symbolic link data - device number, inode number
    "T",  # 7.10 T - Title for pr - Title text (when file printed with p)
    "U",  # 7.11 U - Unlink data file - File to unlink
    "W",  # 7.12 W - Width of output - width count
    "1",  # 7.13 1 - troff R font - File name
    "2",  # 7.14 2 - troff I font - File name
    "3",  # 7.15 3 - troff B font - File name
    "4",  # 7.16 4 - troff S font - File name
    "c",  # 7.17 c - Plot CIF file - File to plot
    "d",  # 7.18 d - Print DVI file - File to print
    "f",  # 7.19 f - Print formatted file - File to print
    "g",  # 7.20 g - Print plot file - File to plot
    "k",  # 7.21 k - Reserved for use by Kerberized LPR clients and servers. (not defined)
    "l",  # 7.22 l - Print file leaving control characters - File to print (similar to f)
    "n",  # 7.23 n - Print ditroff output file - File to print
    "o",  # 7.24 o - Print postcript output file - File to print
    "p",  # 7.25 p - Print file with "pr" format - File to print (see N, T)
    "r",  # 7.26 r - File to print with FORTRAN carriage control - file to print
    "t",  # 7.27 t - Print troff output file - File to print
    "v",  # 7.28 v - Print raster file - File to print
    "z"  # 7.29 z - Reserved for future use with the Palladium print system. (not defined)
]


class LPD(IFuzzer):
    """LPD Fuzzer

    Define all LPD operations:
    Get Short Queue
    Get Long Queue
    Print Data File
    Remove Job
    """

    name = 'lpd'

    @staticmethod
    def get_requests() -> List[callable]:
        """Get possible requests"""
        return [LPD.long_queue, LPD.short_queue, LPD.ctrl_file, LPD.data_file, LPD.remove_job]

    @staticmethod
    def define_nodes(*args, **kwargs) -> None:

        # Long Queue
        s_initialize('long_queue')
        s_static(b'\x04', name='command')
        s_string('lp', name='queue_name')
        s_delim(b' ')
        s_string('root', name='username')
        s_delim(b'\n')

        # --------------------------------------------------------------- #

        # Short Queue
        s_initialize('short_queue')
        s_static(b'\x03', name='command')
        s_string('lp', name='queue_name')
        s_delim(b' ')
        s_string('root', name='username')
        s_delim(b'\n')

        # --------------------------------------------------------------- #

        s_initialize('recv_job')
        s_static(b'\x02', name='command')
        s_string('lp', name='queue_name')
        s_delim(b'\n')

        # --------------------------------------------------------------- #

        # Ctrl File
        s_initialize('ctrl_file')
        s_static(b'\x02', name='subcommand')
        s_size('ctrlfiledata', output_format='ascii', name='ctrl_file_size')
        s_delim(b' ')
        s_string('cfA337hostname', name='ctrl_file_name')
        s_delim(b'\n')
        with s_block('ctrlfiledata'):
            s_group(b'opts', values=CTRL_FILE_OPTIONS)
            s_string('root', mutation_types=['long'], name='ctrlfile_opt_val', )
            s_delim(b'\n', name='ctrlfile_option_delim')
        s_repeat("ctrlfiledata", min_reps=0, max_reps=1000, step=100)
        s_delim(b'\x00', name='ctrlfile_end')

        # --------------------------------------------------------------- #

        # Non fuzzable Ctrl file and Data file
        s_initialize('nofuzz_ctrl_file')  # CTRL file with options just to print!
        s_static(b'\x02', name='subcommand')
        s_size('ctrlfiledata', output_format='ascii', name='ctrl_file_size', fuzzable=False)
        s_delim(b' ', fuzzable=False)
        s_string('cfA337hostname', name='ctrl_file_name', fuzzable=False)
        s_delim(b'\n', fuzzable=False)
        s_static(b'Hhostname\nProot\nMroot\nfdfB337hostname\nUdfB337hostname\nN/etc/passwd\n\x00', name='ctrlfiledata')

        s_initialize('data_file')
        s_static(b'\x03', name='subcommand')
        s_size('data_file', output_format='ascii', name='data_file_size')
        s_delim(b' ')
        s_string('dfB337hostname', name='data_file_name')
        s_delim(b'\n')
        s_string(' ' * 5, name='data_file')  # 5 spaces to, in case of printing, don't waste #savetheamazonforest xD
        s_delim(b'\x00', name='data_file_end')

        # --------------------------------------------------------------- #

        s_initialize('remove_job')
        s_static(b'\x05', name='command')
        s_string('lp', name='queue_name')
        s_delim(b' ')
        s_string('root', name='user_name')
        s_delim(b' ')
        s_string('337', name='job_number')
        s_delim(b'\n')

        # --------------------------------------------------------------- #

        # Abort
        s_initialize('abort')
        s_static(b'\x01')

    @staticmethod
    def long_queue(session: Session) -> None:
        session.connect(s_get('long_queue'))

    @staticmethod
    def short_queue(session: Session) -> None:
        session.connect(s_get('short_queue'))

    @staticmethod
    def ctrl_file(session: Session) -> None:
        session.connect(s_get('recv_job'))
        session.connect(s_get('recv_job'), s_get('ctrl_file'))
        session.connect(s_get('ctrl_file'), s_get('abort'))

    @staticmethod
    def data_file(session: Session) -> None:
        session.connect(s_get('recv_job'))
        session.connect(s_get('recv_job'), s_get('nofuzz_ctrl_file'))
        session.connect(s_get('nofuzz_ctrl_file'), s_get('data_file'))

    @staticmethod
    def remove_job(session: Session) -> None:
        session.connect(s_get('remove_job'))
        session.connect(s_get('remove_job'), s_get('abort'))
