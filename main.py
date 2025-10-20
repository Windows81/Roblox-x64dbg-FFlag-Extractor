import argparse
import builtins
import sys
import enum
import functools
import itertools
import json
import os

from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import DisasmArgType, DisasmInstrType, Instruction, MemPage

LEA_INSTR_SIZE = 7
CALL_INSTR_SIZE = 5


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class flag_type(enum.Enum):
    FString = b'FriendsOnlineUrl'
    # DFString = b'RobloxAnalyticsURL'
    FLog = b'GfxClustersFull'
    FInt = b'StreamingSafeMemWatermarkMB'
    # DFInt = b'DataStoreJobFrequencyInSeconds'
    FFlag = b'NamesOccludedAsDefault'
    # DFFlag = b'DebugAnalyticsSendUserId'

    def get_value_type(self):
        match self:
            case flag_type.FFlag:
                return builtins.bool
            case flag_type.FInt | flag_type.FLog:
                return builtins.int
            case flag_type.FString:
                return builtins.str


def is_exe_64_bit(path: str) -> bool:
    with open(path, 'rb') as r:

        r.seek(0x3C, os.SEEK_SET)
        coff_offset = int.from_bytes(r.read(4), 'little')

        r.seek(coff_offset, os.SEEK_SET)
        assert r.read(4) == b'\x50\x45\x00\x00'
        arch = r.read(2)

    match arch:
        case b'\x64\x86':
            return True
        case b'\x4c\x01':
            return False
        case _:
            return False


@functools.cache
def organise_map(session: X64DbgClient) -> dict[str, MemPage]:
    result = dict[str, MemPage]()
    add_to_map = False
    for m in session.memmap():
        if m.info.endswith('.exe'):
            add_to_map = True
            continue
        if not add_to_map:
            continue
        if not m.info.startswith(' ".'):
            continue
        key = m.info[2:-1]
        if key in result:
            break
        result[key] = m
    return result


@functools.cache
def iterate_ref(session: X64DbgClient, *a: int):
    assert session.cmd_sync(
        'reffind '+','.join('%x' % v for v in a)
    )
    (ref_count, _) = session.eval_sync('ref.count()')

    return [
        session.eval_sync('ref.addr(%x)' % i)[0]
        for i in range(ref_count)
    ]


@functools.cache
def find_flag_name_address(session: X64DbgClient, word: bytes):
    region_map = organise_map(session)
    assert session.cmd_sync('find %x,"%s"' % (
        region_map['.rdata'].base_address,
        (b'\0' + word + b'\0').hex(),
    ))
    (word_base, _) = session.eval_sync('$result+1')
    return word_base


@functools.cache
def find_lea_from_addr(session: X64DbgClient, memory_addr: int):
    region_map = organise_map(session)
    refs = iterate_ref(
        session,
        memory_addr,
        region_map['.text'].base_address,
        region_map['.text'].region_size,
    )
    assert len(refs) == 1
    lea_addr = refs[0]

    lea_ins = session.disassemble_at(lea_addr)
    assert lea_ins is not None
    assert lea_ins.instruction.startswith('lea')
    return (lea_ins, lea_addr)


@functools.cache
def find_mem_lea_from_name_lea(session: X64DbgClient, lea_addr: int):
    offset = -LEA_INSTR_SIZE
    ins = session.disassemble_at(lea_addr+offset)
    assert ins is not None
    assert ins.instruction.startswith('lea')
    return (offset, ins)


def read_string(session: X64DbgClient, addr: int):
    (strlen, _) = session.eval_sync('strlen(utf8((%x))' % addr)
    if strlen == 0:
        return None
    return session.read_memory(addr, strlen)


@functools.cache
def trace_down_until_branch(session: X64DbgClient, base_addr: int, skip_current: bool = True, count: int = 1):
    offset = 0
    while True:
        ins = session.disassemble_at(base_addr + offset)
        assert ins is not None

        if (
            ins.type == DisasmInstrType.Branch and
            not (skip_current and offset == 0)
        ):
            count -= 1
            if count == 0:
                return (offset, ins)

        offset += ins.instr_size
        continue


@functools.cache
def process_call_stuff(session: X64DbgClient, call_arg: int, load_offset: int):
    region_map = organise_map(session)
    call_refs = iterate_ref(
        session,
        call_arg,
        region_map['.text'].base_address,
        region_map['.text'].region_size,
    )

    def gen():
        for addr in call_refs:
            orig_offset = load_offset + LEA_INSTR_SIZE
            load_ins = session.disassemble_at(addr - load_offset)
            orig_ins = session.disassemble_at(addr - orig_offset)
            assert load_ins is not None
            assert orig_ins is not None
            if not load_ins.instruction.startswith('lea'):
                continue
            if not orig_ins.instruction.startswith('lea'):
                continue
            yield (load_ins.arg[1].constant, orig_ins.arg[1].constant)

    return list(gen())


@functools.cache
def get_string_load_places(session: X64DbgClient, flag_t: flag_type):
    flag_name_mem_addr = find_flag_name_address(session, flag_t.value)
    flag_name_addr = find_lea_from_addr(session, flag_name_mem_addr)[1]
    (_, flag_load_ins) = find_mem_lea_from_name_lea(session, flag_name_addr)

    region_map = organise_map(session)
    orig_lea_addr = iterate_ref(
        session,
        flag_load_ins.arg[1].constant,
        region_map['.text'].base_address,
        region_map['.text'].region_size,
    )[0]

    call_stuff = [
        trace_down_until_branch(session, orig_lea_addr, count=i+1)
        for i in range(2)
    ]

    return dict(itertools.chain(*(
        process_call_stuff(session, call_ins.arg[0].constant, load_offset)
        for (load_offset, call_ins) in call_stuff
    )))


def read_value(session: X64DbgClient, flag_t: flag_type, name_addr: int):
    (val_offset, val_ins) = find_mem_lea_from_name_lea(session, name_addr)
    val_ref = val_ins.arg[1].constant
    match flag_t.get_value_type():

        case builtins.bool:
            val = session.read_memory(val_ref, 1)[0]
            assert val | 0b0001
            return val > 0

        case builtins.int:
            return session.read_dword(val_ref)

        case builtins.str:
            orig_ref = get_string_load_places(session, flag_t)[val_ref]
            result = read_string(session, orig_ref) or b''
            return result.decode()

        case _:
            assert False


@functools.cache
def find_addrs_into_branch(session: X64DbgClient, func_addr: int, lea_offset: int):
    region_map = organise_map(session)

    def gen():
        for a in iterate_ref(
            session,
            func_addr,
            region_map['.text'].base_address,
            region_map['.text'].region_size,
        ):

            lea_addr = a - lea_offset
            lea_ins = session.disassemble_at(lea_addr)
            assert lea_ins is not None
            assert lea_ins.instruction.startswith('lea')

            lea_ref = lea_ins.arg[1].constant
            assert lea_ins.arg[1].type == DisasmArgType.Memory
            yield (lea_ref, lea_addr)

    return list(gen())


def process_of_type(session: X64DbgClient, flag_t: flag_type):
    flag_name_addr = find_flag_name_address(session, flag_t.value)
    eprint(
        '%s [template flag `%s` found at %X]' %
        (flag_t.name, flag_t.value.decode(), flag_name_addr)
    )
    (_, lea_addr) = find_lea_from_addr(session, flag_name_addr)
    (call_offset, call_ins) = trace_down_until_branch(session, lea_addr)
    call_addr = call_ins.arg[0].constant
    eprint(
        '%s [jmp/call found at %X]' %
        (flag_t.name, call_addr)
    )
    flag_name_addrs = find_addrs_into_branch(session, call_addr, call_offset)
    eprint(
        '%s [a number of %d refs are found]' %
        (flag_t.name, len(flag_name_addrs))
    )
    flag_names = [
        flag_t.name + (read_string(session, r) or b'').decode()
        for (r, a) in flag_name_addrs
    ]
    eprint(
        '%s [string indicies finished loading]' %
        (flag_t.name)
    )
    flag_values = [
        read_value(session, flag_t, a)
        for (r, a) in flag_name_addrs
    ]
    eprint(
        '%s [default values finished loading]' %
        (flag_t.name)
    )
    return dict(zip(flag_names, flag_values))


def run(path: str) -> None:
    session = X64DbgClient('x64dbg' if is_exe_64_bit(path) else 'x32dbg')
    session.start_session(path)
    session.wait_until_debugging()
    result = dict(itertools.chain(*(
        process_of_type(session, t).items()
        for t in flag_type
    )))
    print(json.dumps(result, indent='\t'))
    session.terminate_session()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('debug_path', type=str)
    args = parser.parse_args()
    run(
        args.debug_path,
        # r'c:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Studio\RobloxStudioBeta.exe'
    )
