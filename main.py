import sys
import enum
import functools
import itertools
import json
import os

from x64dbg_automate import X64DbgClient
from x64dbg_automate.models import DisasmInstrType, MemPage

LEA_INSTR_SIZE = 7
CALL_INSTR_SIZE = 5


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


class flag_type(enum.Enum):
    FString = b'FriendsOnlineUrl'
    DFString = b'RobloxAnalyticsURL'
    FLog = b'GfxClustersFull'
    FInt = b'PGSPenetrationMarginMax'
    DFInt = b'DataStoreJobFrequencyInSeconds'
    FFlag = b'NamesOccludedAsDefault'
    DFFlag = b'DebugAnalyticsSendUserId'


def is_64_bit(path: str) -> bool:
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


def iterate_ref(session: X64DbgClient, *a: int) -> list[int]:
    assert session.cmd_sync(
        'reffind '+','.join('%x' % v for v in a)
    )
    (ref_count, _) = session.eval_sync('ref.count()')

    result: list[int] = []
    for i in range(ref_count):
        (v, s) = session.eval_sync('ref.addr(%x)' % i)
        assert s
        result.append(v)

    return result


def find_flag_address(session: X64DbgClient, word: bytes = b'WeakThreadRef') -> int:
    region_map = organise_map(session)
    assert session.cmd_sync('find %x,"%s"' % (
        region_map['.rdata'].base_address,
        (b'\0' + word + b'\0').hex(),
    ))
    (word_base, _) = session.eval_sync('$result+1')
    return word_base


def find_func_address(session: X64DbgClient, word_base: int) -> int:
    region_map = organise_map(session)
    assert session.cmd_sync('reffind %x,%x,%x' % (
        word_base,
        region_map['.text'].base_address,
        region_map['.text'].region_size,
    ))

    (ref_count, _) = session.eval_sync('ref.count()')
    assert ref_count == 1
    (ref_addr, _) = session.eval_sync('ref.addr(0)')

    lea_ins = session.disassemble_at(ref_addr)
    assert lea_ins is not None
    assert lea_ins.instruction.startswith('lea')

    call_ins = session.disassemble_at(ref_addr + LEA_INSTR_SIZE)
    assert call_ins is not None
    assert call_ins.type == DisasmInstrType.Branch

    result = call_ins.arg[0].constant
    assert result > 0
    return result


def read_string(session: X64DbgClient, addr: int):
    (strlen, _) = session.eval_sync('strlen(utf8((%x))' % addr)
    if strlen == 0:
        return None
    return session.read_memory(addr, strlen)


def read_value(session: X64DbgClient, addr: int, key: flag_type):
    val_addr = addr - LEA_INSTR_SIZE
    val_ins = session.disassemble_at(val_addr)
    assert val_ins is not None
    assert val_ins.instruction.startswith('lea')

    val_ref = val_ins.arg[1].constant
    match key:

        case flag_type.FFlag | flag_type.DFFlag:
            val = session.read_memory(val_ref, 1)[0]
            assert val | 0b0001
            return val > 0

        case flag_type.FInt | flag_type.DFInt | flag_type.FLog:
            return session.read_dword(val_ref)

        case flag_type.FString | flag_type.DFString:
            for ref_addr in iterate_ref(session, val_ref, val_addr - 0x208, 0x200):
                lea_addr = ref_addr - LEA_INSTR_SIZE
                lea_ins = session.disassemble_at(lea_addr)
                assert lea_ins is not None
                if not lea_ins.instruction.startswith('lea'):
                    continue

                lea_ref = lea_ins.arg[1].constant
                if lea_ref == 0:
                    continue

                result = read_string(session, lea_ref)
                if result is None:
                    continue
                return result.decode()

            return ''


def find_flags_into_func(session: X64DbgClient, func_addr: int):
    region_map = organise_map(session)
    for a in iterate_ref(
        session,
        func_addr,
        region_map['.text'].base_address,
        region_map['.text'].region_size,
    ):

        call_ins = session.disassemble_at(a)
        assert call_ins is not None
        assert call_ins.type == DisasmInstrType.Branch

        lea_addr = a - LEA_INSTR_SIZE
        lea_ins = session.disassemble_at(lea_addr)
        assert lea_ins is not None
        assert lea_ins.instruction.startswith('lea')

        lea_ref = lea_ins.arg[1].constant
        assert lea_ref > 0
        yield (lea_ref, lea_addr)


def process_of_type(session: X64DbgClient, flag_t: flag_type):
    flag_addr = find_flag_address(session, flag_t.value)
    eprint(
        '%s [template flag `%s` found at %x]' %
        (flag_type.name, flag_type.value, flag_addr)
    )
    func_addr = find_func_address(session, flag_addr)
    eprint(
        '%s [jmp/call found at %x]' %
        (flag_type.name, func_addr)
    )
    flag_addrs = list(find_flags_into_func(session, func_addr))
    eprint(
        '%s [a number of %d refs are found]' %
        (flag_type.name, len(flag_addrs))
    )
    flag_strings = (
        flag_t.name + (read_string(session, r) or b'').decode()
        for (r, i) in flag_addrs
    )
    flag_values = (
        read_value(session, i, flag_t)
        for (r, i) in flag_addrs
    )
    return dict(zip(flag_strings, flag_values))


def run(path: str) -> None:
    session = X64DbgClient('x64dbg' if is_64_bit(path) else 'x32dbg')
    session.start_session(path)
    session.wait_until_debugging()
    result = dict(itertools.chain(*(
        process_of_type(session, t).items()
        for t in flag_type
    )))
    print(json.dumps(result, indent='\t'))
    session.terminate_session()


if __name__ == '__main__':
    run(
        input('Enter the name of the executable onto which you wish to notate FFlags: ')
        # r'c:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Studio\RobloxStudioBeta.exe'
    )
