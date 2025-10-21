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


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class flag_type(enum.Enum):
    FFlag = b'LockViolationInstanceCrash'
    FInt = b'DataStoreJobFrequencyInSeconds'  # b'StreamingSafeMemWatermarkMB'
    FString = b'FriendsOnlineUrl'  # b'RobloxAnalyticsURL'
    FLog = b'GfxClustersFull'

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


def get_memory_ref(ins: Instruction):
    match ins.instruction.split(' ', 1)[0]:

        case 'lea' | 'mov' | 'push' | 'xmm' | 'movaps' | 'movups':
            for i in (0, 1):
                c = ins.arg[i].constant
                if c > 0x1000:
                    return c
        case _:
            pass
    return


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
def iterate_ref(session: X64DbgClient, addr_to_find: int, fr: int, sz: int, max_iter: int = 0x3000000):
    '''
    Iterates through the reference of a given address and returns a list of call addresses.
    Multiple calls to `reffind` are necessary since the program will crash if they are all done at once.
    '''
    def gen(fr: int, sz: int):
        assert session.cmd_sync('reffind %x,%x,%x' % (addr_to_find, fr, sz))
        (ref_count, _) = session.eval_sync('ref.count()')
        for i in range(ref_count):
            yield session.eval_sync('ref.addr(%x)' % i)[0]

    return list(itertools.chain(*(
        gen(fr=i, sz=min(i + max_iter - fr, sz))
        for i in range(fr, fr + sz, max_iter)
    )))


@functools.cache
def find_word_in_memory(session: X64DbgClient, word: bytes):
    '''
    Finds a complete string `word` and returns the address.
    '''
    region_map = organise_map(session)
    assert session.cmd_sync('find %x,"%s"' % (
        region_map['.rdata'].base_address,
        (b'\0' + word + b'\0').hex(),
    ))
    (word_base, _) = session.eval_sync('$result')
    assert word_base > 0
    return word_base + 1


@functools.cache
def find_lea_from_addr(session: X64DbgClient, memory_addr: int):
    region_map = organise_map(session)
    refs = iterate_ref(
        session,
        memory_addr,
        region_map['.text'].base_address,
        region_map['.text'].region_size,
    )
    # assert len(refs) == 1
    lea_addr = refs[0]

    lea_ins = session.disassemble_at(lea_addr)
    assert lea_ins is not None
    lea_ref = get_memory_ref(lea_ins)
    assert lea_ref is not None
    return (lea_ref, lea_addr)


@functools.cache
def find_mem_lea_from_name_lea(session: X64DbgClient, lea_addr: int):
    lea_ins = session.disassemble_at(lea_addr)
    assert lea_ins is not None
    offset = -lea_ins.instr_size

    ins = session.disassemble_at(lea_addr+offset)
    assert ins is not None
    ref = get_memory_ref(ins)
    assert ref is not None
    return (offset, ref)


def read_string(session: X64DbgClient, addr: int, can_start_in_middle: bool = False):
    if can_start_in_middle:
        addr += session.read_memory(addr - 0x100, 0x100).rfind(b'\0') - 0xff
    (strlen, _) = session.eval_sync('strlen(utf8((%x))' % addr)
    if strlen == 0:
        return None
    return session.read_memory(addr, strlen)


@functools.cache
def trace_down_until_branches(session: X64DbgClient, base_addr: int, skip_current: bool = True, count: int = 1):
    offset = 0
    while True:
        ins = session.disassemble_at(base_addr + offset)
        assert ins is not None

        if ins.instruction == 'int3':
            return

        if (
            ins.type == DisasmInstrType.Branch and
            not (skip_current and offset == 0)
        ):
            yield (offset, ins)
            count -= 1
            if count == 0:
                return

        offset += ins.instr_size
        continue


@functools.cache
def process_call_stuff(session: X64DbgClient, call_arg: int, load_offset: int, orig_offset: int):
    region_map = organise_map(session)
    call_refs = iterate_ref(
        session,
        call_arg,
        region_map['.text'].base_address,
        region_map['.text'].region_size,
    )

    def gen():
        for addr in call_refs:
            load_ins = session.disassemble_at(addr - load_offset)
            assert load_ins is not None
            orig_ins = session.disassemble_at(addr - orig_offset)
            assert orig_ins is not None

            load_ref = get_memory_ref(load_ins)
            orig_ref = get_memory_ref(orig_ins)
            if load_ref is None or orig_ref is None:
                continue
            yield (load_ref, orig_ref)

    return list(gen())


@functools.cache
def get_string_load_places(session: X64DbgClient):
    flag_name_mem_addr = find_word_in_memory(session, b'FriendsOnlineUrl')
    (_, flag_name_addr) = find_lea_from_addr(session, flag_name_mem_addr)
    (_, flag_load_ref) = find_mem_lea_from_name_lea(session, flag_name_addr)

    default_val_mem_addr = find_word_in_memory(session, b'/my/friendsonline')
    (_, default_val_addr) = find_lea_from_addr(session, default_val_mem_addr)

    lea_addr = min(
        iterate_ref(
            session,
            flag_load_ref,
            default_val_addr - 0x100,
            0x200,
        ),
        key=lambda a: abs(a - default_val_addr)
    )
    default_offset = lea_addr - default_val_addr

    call_stuff = list(trace_down_until_branches(
        session,
        lea_addr,
        count=2,
    ))

    return dict(itertools.chain(*(
        process_call_stuff(
            session,
            call_ins.arg[0].constant,
            lea_offset,
            lea_offset + default_offset,
        )
        for (lea_offset, call_ins) in call_stuff
    )))


def read_value(session: X64DbgClient, flag_t: flag_type, name_addr: int):
    (val_offset, val_ref) = find_mem_lea_from_name_lea(session, name_addr)
    assert val_ref is not None
    match flag_t:

        case flag_type.FFlag:
            val = session.read_memory(val_ref, 1)[0]
            assert val | 0b0001
            return val > 0

        case flag_type.FInt:
            return session.read_dword(val_ref)

        case flag_type.FLog:
            return session.read_memory(val_ref, 1)[0]

        case flag_type.FString:
            places = get_string_load_places(session)
            orig_ref = places.get(val_ref, None)
            if orig_ref is None:
                eprint('WARNING: unable to get flag at %X' % name_addr)
                return

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

            lea_ref = get_memory_ref(lea_ins)
            if lea_ref is None:
                continue
            yield (lea_ref, lea_addr)

    return list(gen())


def process_of_type(session: X64DbgClient, flag_t: flag_type):
    flag_name_addr = find_word_in_memory(session, flag_t.value)
    eprint(
        '[%s] template flag `%s` found at %X' %
        (flag_t.name, flag_t.value.decode(), flag_name_addr)
    )
    (_, lea_addr) = find_lea_from_addr(session, flag_name_addr)
    eprint(
        '[%s] lea for flag name found at %X' %
        (flag_t.name, lea_addr)
    )
    (call_offset, call_ins) = next(trace_down_until_branches(session, lea_addr))
    call_addr = call_ins.arg[0].constant
    eprint(
        '[%s] jmp/call found from %X to %X' %
        (flag_t.name, lea_addr + call_offset, call_addr)
    )
    flag_name_addrs = find_addrs_into_branch(session, call_addr, call_offset)
    eprint(
        '[%s] a number of %d refs are found' %
        (flag_t.name, len(flag_name_addrs))
    )
    flag_names = (
        (read_string(session, r) or b'').decode()
        for (r, a) in flag_name_addrs
    )
    return zip(flag_names, flag_name_addrs)


def process(session: X64DbgClient, extract_default_flags: bool, extract_default_strings: bool):
    def gen():
        for flag_t in flag_type:
            if flag_t.get_value_type() == builtins.str:
                extract = extract_default_strings
            else:
                extract = extract_default_flags

            for name, (ref, addr) in process_of_type(session, flag_t):
                json_val = (f'ref: %X; addr: %X' % (ref, addr),)

                result = None
                if extract:
                    result = read_value(session, flag_t, addr)
                if result is not None:
                    json_val = (*json_val, result)

                key = flag_t.name + name
                yield (key, json_val)

    return dict(gen())


def run(debug_path: str, *a, **kwa) -> None:
    session = X64DbgClient('x64dbg' if is_exe_64_bit(debug_path) else 'x32dbg')
    try:
        session.start_session(debug_path)
        session.wait_until_debugging()

        print(json.dumps(process(session, *a, **kwa), indent='\t'))
    finally:
        session.terminate_session()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('debug_path', type=str)
    parser.add_argument(
        '--extract_default_flags',
        '-df',
        action='store_true',
    )
    parser.add_argument(
        '--extract_default_strings',
        '-ds',
        action='store_true',
    )
    args = parser.parse_args()
    run(**args.__dict__)
    # r'c:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Studio\RobloxStudioBeta.exe'
