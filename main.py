import argparse
import builtins
import sys
import enum
import functools
import itertools
import json
import os

from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import DisasmInstrType, Instruction, MemPage


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class flag_type(enum.Enum):
    FFlag = b'LockViolationInstanceCrash'
    FInt = b'StreamingSafeMemWatermarkMB'  # b'DataStoreJobFrequencyInSeconds'
    FString = b'FriendsOnlineUrl'  # b'RobloxAnalyticsURL'
    FLog = b'GfxClustersFull'


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


def get_memory_ptr(ins: Instruction):
    '''
    The x86 language gives you a variety of ways of reading or writing data to a particular address.
    Rōblox has been known to use many different instruction types to grab the same data for the same purpose.
    For example, Studio v347 uses `push` to add the name of an FFlag as an argument for the next `call`.
    However, Studio v463 uses `lea` into a register `rcx` for the exact same purpose.
    '''
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
def find_string_in_memory(session: X64DbgClient, s: bytes):
    '''
    Finds a *complete* string and returns the address.
    Throws if that word does not exist.
    '''
    region_map = organise_map(session)
    assert session.cmd_sync('find %x,"%s"' % (
        region_map['.rdata'].base_address,
        (b'\0%s\0' % s).hex(),
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
    lea_ptr = get_memory_ptr(lea_ins)
    assert lea_ptr is not None
    return (lea_addr, lea_ptr)


@functools.cache
def find_mem_lea_from_name_lea(session: X64DbgClient, name_lea_addr: int):
    '''
    Definitions that I made up:
    - `name_lea`: the memory-read instruction with an address to the *name* of the flag.
    Can be `lea`, `push`, `mov`, etc.
    - `mem_lea`: the memory-read instruction with an address to the *memory location* of that same flag.
    Can be `lea`, `push`, `mov`, etc.

    This function takes advantage of the fact that:
    - `mem_lea` directly precedes `name_lea`.
    - `mem_lea` and `name_lea` both have the same instruction size.

    This has been validated in various Studio versions from 347 up to 695.
    '''
    lea_ins = session.disassemble_at(name_lea_addr)
    assert lea_ins is not None
    addr = name_lea_addr - lea_ins.instr_size

    ins = session.disassemble_at(addr)
    assert ins is not None
    ptr = get_memory_ptr(ins)
    assert ptr is not None
    return (addr, ptr)


def read_string(session: X64DbgClient, addr: int, can_start_in_middle: bool = False):
    '''
    Reads a string beginning at a specific memory address.
    '''
    if can_start_in_middle:
        addr += session.read_memory(addr - 0x100, 0x100).rfind(b'\0') - 0xff
    (strlen, _) = session.eval_sync('strlen(utf8((%x))' % addr)
    if strlen == 0:
        return None
    return session.read_memory(addr, strlen)


@functools.cache
def trace_down_until_branches(session: X64DbgClient, base_addr: int, skip_current: bool = True, count: int = 1):
    '''
    Generates a list of branch statements which follow `base_addr`.
    Limited by `count`, which if set to -1, can run up to the next `int3` instruction
    '''
    addr = base_addr
    while True:
        ins = session.disassemble_at(addr)
        assert ins is not None

        if ins.instruction == 'int3':
            return

        if (
            ins.type == DisasmInstrType.Branch and
            not (skip_current and addr == base_addr)
        ):
            yield (addr, ins)
            count -= 1
            if count == 0:
                return

        addr += ins.instr_size
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

            load_ref = get_memory_ptr(load_ins)
            orig_ref = get_memory_ptr(orig_ins)
            if load_ref is None or orig_ref is None:
                continue
            yield (load_ref, orig_ref)

    return list(gen())


@functools.cache
def get_string_load_places(session: X64DbgClient):
    flag_name_mem_addr = find_string_in_memory(session, b'FriendsOnlineUrl')
    (flag_name_addr, _) = find_lea_from_addr(session, flag_name_mem_addr)
    (_, flag_load_ref) = find_mem_lea_from_name_lea(session, flag_name_addr)

    default_val_mem_addr = find_string_in_memory(session, b'/my/friendsonline')
    (default_val_addr, _) = find_lea_from_addr(session, default_val_mem_addr)

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
            call_addr - lea_addr,
            call_addr - lea_addr + default_offset,
        )
        for (call_addr, call_ins) in call_stuff
    )))


def read_value(session: X64DbgClient, flag_t: flag_type, mem_addr: int):
    ins = session.disassemble_at(mem_addr)
    assert ins is not None

    val_ref = get_memory_ptr(ins)
    assert val_ref is not None

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


def to_rva(session: X64DbgClient, addr: int):
    (result, success) = session.eval_sync('mod.rva(%x)' % addr)
    assert success
    return result


@functools.cache
def find_addrs_into_branch(session: X64DbgClient, func_addr: int, lea_offset: int):
    region_map = organise_map(session)

    def gen():
        for lea_addr in iterate_ref(
            session,
            func_addr,
            region_map['.text'].base_address,
            region_map['.text'].region_size,
        ):

            lea_addr = lea_addr - lea_offset
            lea_ins = session.disassemble_at(lea_addr)
            assert lea_ins is not None

            lea_ref = get_memory_ptr(lea_ins)
            if lea_ref is None:
                continue
            yield (lea_addr, lea_ref)

    return list(gen())


def get_flags_of_type(session: X64DbgClient, flag_t: flag_type):
    flag_name_addr = find_string_in_memory(session, flag_t.value)
    eprint(
        '    [%s] template flag `%s` found at :$%X' %
        (
            flag_t.name,
            flag_t.value.decode(),
            to_rva(session, flag_name_addr),
        )
    )
    (lea_addr, _) = find_lea_from_addr(session, flag_name_addr)
    eprint(
        '    [%s] lea for flag name found at :$%X' %
        (
            flag_t.name,
            to_rva(session, lea_addr),
        )
    )
    (call_addr, call_ins) = next(trace_down_until_branches(session, lea_addr))
    call_ptr = call_ins.arg[0].constant
    call_offset = call_addr - lea_addr
    eprint(
        '    [%s] jmp/call found from :$%X to :$%X' %
        (
            flag_t.name,
            to_rva(session, call_addr),
            to_rva(session, call_ptr),
        )
    )
    flag_name_addrs = find_addrs_into_branch(session, call_ptr, call_offset)
    eprint(
        '    [%s] a number of %d refs are found' %
        (flag_t.name, len(flag_name_addrs))
    )
    flag_names = (
        (read_string(session, ptr) or b'').decode()
        for (_, ptr) in flag_name_addrs
    )
    flag_mem_addrs = (
        find_mem_lea_from_name_lea(session, addr)
        for (addr, _) in flag_name_addrs
    )
    return zip(flag_names, flag_name_addrs, flag_mem_addrs)


def process(session: X64DbgClient, extract_default_flags: bool, extract_default_strings: bool, add_flag_labels: bool):
    for flag_t in flag_type:
        if flag_t == flag_type.FString:
            extract_default = extract_default_strings
        else:
            extract_default = extract_default_flags

        flags_of_type = get_flags_of_type(session, flag_t)
        for name, (name_addr, name_ptr), (val_addr, val_ptr) in flags_of_type:

            addr_str = 'load = :$%X; mem_val = :$%X; mem_name = :$%X' % (
                to_rva(session, val_addr),
                to_rva(session, val_ptr),
                to_rva(session, name_ptr),
            )
            json_val = (addr_str,)

            result = None
            if extract_default:
                result = read_value(session, flag_t, val_addr)

            if result is not None:
                json_val = (*json_val, result)
            json_key = '%s%s' % (flag_t.name, name)

            if add_flag_labels:
                session.set_label_at(
                    val_ptr,
                    '%s::%s' % (flag_t.name, name),
                )

            yield (json_key, json_val)


def run(debug_path: str, *a, **kwa) -> None:
    session = X64DbgClient('x64dbg' if is_exe_64_bit(debug_path) else 'x32dbg')
    try:
        eprint('>>> "%s"' % debug_path)
        session.start_session(debug_path)
        session.wait_until_debugging()

        result = dict(process(session, *a, **kwa))
        print(json.dumps(result, indent='\t'))
        eprint('<<< "%s"' % debug_path)
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
    parser.add_argument(
        '--add_flag_labels',
        help='Adds the flag-name labels to your x64dbg database',
        action='store_true',
    )
    args = parser.parse_args()
    # r'c:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Studio\RobloxStudioBeta.exe'
    run(**args.__dict__)
