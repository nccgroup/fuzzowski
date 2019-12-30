import pygments
from prompt_toolkit import print_formatted_text
from pygments.formatters.terminal256 import Terminal256Formatter
from pygments.lexers.python import Python3Lexer
from prompt_toolkit.formatted_text import PygmentsTokens
from prompt_toolkit.styles.pygments import style_from_pygments_cls
from pygments.styles import get_style_by_name

from fuzzowski.mutants import Request, Mutant
from fuzzowski.connections.target import Target
from fuzzowski.connections.socket_connection import SocketConnection


def repr_input_bytes_as_python(input_bytes, orig, first=False, last=False):
    try:
        mod = len(input_bytes) % len(orig)
        mult = len(input_bytes) // len(orig)

        representation = ''
        if not first:
            representation += '+ '
        if input_bytes != orig \
                and mult > 0 \
                and ((mod == 0 and input_bytes == (orig * mult)) or (mod != 0 and input_bytes[:-mod] == (orig * mult))):
            if mod == 0:
                representation += "{} * {} +".format(repr(orig), mult)
            else:
                representation += "{} * {} + {}".format(repr(orig), mult, repr(input_bytes[-mod:]))
        elif input_bytes != orig \
                and len(input_bytes) > 0 and input_bytes == (chr(input_bytes[0]) * len(input_bytes)).encode('utf8'):
            representation += '{} * {} +'.format(chr(input_bytes[0]).encode('utf8'), len(input_bytes))
        else:
            representation = repr(input_bytes)
    except ZeroDivisionError:
        representation = repr(input_bytes)
    return representation


# --------------------------------------------------------------- #


def block_to_python(block: Mutant, indent=0, mutant=None, first=False) -> str:
    block_code = ''
    space = ' ' * indent
    if mutant is None and hasattr(block, 'mutant'):
        mutant = block.mutant
    if hasattr(block, 'stack'):
        block_code += '{}#{} - {}\n'.format(space*2, block.__class__.__name__,  block.name)
        for child_block in block.stack:
            block_code += block_to_python(child_block, indent=indent*2, mutant=mutant)

            if child_block == mutant:
                block_code += ' (mutant, size={}, orig val: {})'.format(len(mutant.render()), child_block.original_value)
            block_code += '\n'
    else:
        b_name = block.__class__.__name__
        if block.name is not None:
            b_name += ' - {}'.format(block.name)
        # block_code += '{}{}  #{}'.format(space, repr(block.render()), b_name)
        block_code += '{}{}  #{}'.format(space,
                                         repr_input_bytes_as_python(block.render(), block.original_value, first=first),
                                         # repr(block.render()),
                                         b_name)

    return block_code

# --------------------------------------------------------------- #


def request_to_python(block: Request, indent=0) -> str:
    block_code = '{} = (\n'.format(block.name.replace('-', '_').replace('.', '_').replace(' ', '_'))
    block_code += block_to_python(block, indent=indent // 2, first=True)
    if '+  #' in block_code.splitlines()[-1]:
        block_code += "b''"
    block_code += ")\n"
    return block_code

# --------------------------------------------------------------- #


def path_to_python(path: list, indent=4) -> str:
    block_code = ''
    for e in path:
        block = e.dst
        block_code += request_to_python(block, indent)
        block_code += '\n'

    return block_code

# --------------------------------------------------------------- #


def print_python(path: list) -> None:
    tokens = []
    block_code = path_to_python(path)
    print(pygments.highlight(block_code, Python3Lexer(), Terminal256Formatter(style='rrt')))

    # tokens.extend(list(pygments.lex(block_code, lexer=Python3Lexer())))
    # print_formatted_text(PygmentsTokens(tokens))

# --------------------------------------------------------------- #


def get_exploit_code(target: Target, path: list,
                  receive_data_after_each_request, receive_data_after_fuzz) -> str:
    blocks_code = ''
    for e in path:
        block = e.dst
        blocks_code += request_to_python(block, indent=4)
        blocks_code += get_send_python(target._target_connection, block.name)
        if receive_data_after_each_request and e != path[-1]:
            blocks_code += 'sock.recv(65535)\n\n'
        if receive_data_after_fuzz and e == path[-1]:
            blocks_code += 'sock.recv(65535)\n\n'

    exploit_code = (
        '#!/usr/bin/env python3\n'
        '\n'
        'import socket\n'
        '\n'
        '{}\n'
        '{}'
        'sock.close()\n'
    ).format(
        get_connect_python(target._target_connection),
        blocks_code
    )
    return exploit_code

# --------------------------------------------------------------- #


def print_poc(target: Target, path: list,
              receive_data_after_each_request, receive_data_after_fuzz) -> None:
    tokens = []

    exploit_code = get_exploit_code(target, path, receive_data_after_each_request, receive_data_after_fuzz)
    print(pygments.highlight(exploit_code, Python3Lexer(), Terminal256Formatter(style='rrt')))

    # tokens.extend(list(pygments.lex(exploit_code, lexer=Python3Lexer())))
    # print_formatted_text(PygmentsTokens(tokens))

# --------------------------------------------------------------- #


def print_packets(path: list, nodes: dict) -> None:
    tokens = []
    for e in path[:-1]:
        node = nodes[e.dst]
        p = node.render()
        line = '{} = {}'.format(node.name.replace('-', '_'), repr(p))
        tokens.extend(list(pygments.lex(line, lexer=Python3Lexer())))

    # p = self.fuzz_node.render()
    node = nodes[path[-1].dst]
    p = node.render()
    line = '{} = {}'.format(node.name.replace('-', '_'), repr(p))

    print(pygments.highlight(line, Python3Lexer(), Terminal256Formatter(style='rrt')))

    # tokens.extend(list(pygments.lex(line, lexer=Python3Lexer())))
    # style = style_from_pygments_cls(get_style_by_name('colorful'))
    # print_formatted_text(PygmentsTokens(tokens), style=style)


# --------------------------------------------------------------- #


def get_connect_python(socket_conn: SocketConnection) -> str:
    """

    :type socket_conn: SocketConnection
    :param socket_conn: SocketConnection
    :return the python code of the create socket and connect calls. Used for printing exploits:
    """
    code = ''

    # Create socket
    if socket_conn.proto == "tcp" or socket_conn.proto == "ssl":
        code += 'sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n'
    elif socket_conn.proto == "udp":
        code += 'sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n'
        if socket_conn.bind:
            code += 'sock.bind(({},{}))\n'.format(repr(socket_conn.bind[0]), socket_conn.bind[1])
        if socket_conn._udp_broadcast:
            code += 'sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)\n'
    elif socket_conn.proto == "raw-l2":
        code += 'sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)\n'
    elif socket_conn.proto == "raw-l3":
        code += 'sock = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM)\n'
    else:
        pass

    # Connect is needed only for TCP protocols
    if socket_conn.proto == "tcp" or socket_conn.proto == "ssl":

        code += '\nsock.connect(({}, {}))\n'.format(repr(socket_conn.host), socket_conn.port)

    # if SSL is requested, then enable it.
    if socket_conn.proto == "ssl":
        code += 'sock = ssl.wrap_socket(self._sock)\n'

    return code


# --------------------------------------------------------------- #


def get_send_python(socket_conn: SocketConnection, varname: str) -> str:
    """

    :type socket_conn: SocketConnection
    :param socket_conn: SocketConnection
    :type varname: str
    :param varname: variable name that will be placed inside the send()
    :return: python code of the send or sendto methods
    """
    code = ''
    if socket_conn.proto in ["tcp", "ssl"]:
        code += 'sock.send({})\n'.format(varname.replace('-', '_'))
    elif socket_conn.proto == "udp":
        code += 'sock.sendto({}, ({}, {}))\n'.format(varname.replace('-', '_'),
                                                     repr(socket_conn.host), socket_conn.port)
    elif socket_conn.proto == "raw-l2":
        code += 'sock.sendto({}, ({}, {}))\n'.format(varname.replace('-', '_'), repr(socket_conn.host), 0)
    elif socket_conn.proto == "raw-l3":
        code += 'sock.sendto({}, ({}, {}, {}, {}, {}))\n'\
            .format(varname.replace('-', '_'),
                    repr(socket_conn.host), repr(socket_conn.ethernet_proto), 0, 0, repr(socket_conn.l2_dst))
    else:
        pass
    return code


# --------------------------------------------------------------- #


