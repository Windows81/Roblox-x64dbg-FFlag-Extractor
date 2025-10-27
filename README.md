# Rōblox FFlag Collector (ft. x64dbg)

This tool requires the use of `x64dbg_automate`, which in turn requires `x64dbg` to be in your system path.

All addresses are stored as RVAs (relative virtual addresses) to account for ASLR (address-space randomisation). In fact, x64dbg's patch format `.1337` also uses RVAs.

Here's an example run:

```ps
python main.py "c:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Studio\RobloxStudioBeta.exe" -df -ds > "./test-studio-v463.json"
```

This program is optimised for different versions of Rōblox Studio. Bitness shouldn't be a problem.

## JSON "Test" Files

Attached in [`./test`](./test) are some flag dumps.

I generate these files on **my machine** using the command in [`./test/test.ps1`](./test/test.ps1).

## How?

Rōblox stores hidden options in what we call FFlags. However, `FFlags` are just one piece of the equation. These just refer to boolean values. Rōblox also supplies other namespaces, i.e. `FInt`, `FString`, and `FLog`.

When Rōblox runs, the values are loaded directly from memory addresses. My program's job is to find these memory addresses and. If `--add_flag_labels` is passed in, they are stored as shortcuts the next time you open your program in x64dbg. It's nice to see:

```patch
0196FACD | 8BC8                     | mov     ecx, eax
0196FACF | 8945 EC                  | mov     dword ptr ss:[ebp - 0x14], eax
0196FAD2 | 8B10                     | mov     edx, dword ptr ds:[eax]
0196FAD4 | FF52 20                  | call    dword ptr ds:[edx + 0x20]
-0196FAD7 | 803D 101D5602 00         | cmp     byte ptr ds:[0x02561D10]
+0196FAD7 | 803D 101D5602 00         | cmp     byte ptr ds:[<FFlag::DebugAdornsDisabled>], 0x0
0196FADE | 0F85 E3000000            | jne     robloxplayerbeta.196FBC7
```

### 1. Finding Template Strings

Throughout the years, the names of flags which are available in Rōblox consistently change. But a few remain in vogue for a long time. The following flag-name strings were selected for their presence (1) in the 2016 source-code leak and (2) included in the `.rdata` memory region in Studio v695:

- **FFlag:** `LockViolationInstanceCrash`
- **FInt:** `StreamingSafeMemWatermarkMB`
- **FString:** `FriendsOnlineUrl`
- **FLog:** `GfxClustersFull`

We _must_ know that the memory location of this string must only be referenced _once_ in the entire program. Otherwise, I would've needed to select another flag. This is because other refs would use said string for a completely different purpose, breaking program continuity.

For example, I used `FFlag::LockViolationInstanceCrash` in finding the names and memory addresses of boolean-valued FFlags.

In Player v463:

```
004E03D0 | 6A 02                    | push    0x2                                                    |
004E03D2 | 68 A4915302              | push    robloxplayerbeta.025391A4
004E03D7 | 68 6885F401              | push    robloxplayerbeta.1F48568                               | 1F48568:"LockViolationInstanceCrash"
004E03DC | E8 3F8C0301              | call    robloxplayerbeta.1519020                               |
004E03E1 | 83C4 0C                  | add     esp, 0xC                                               |
004E03E4 | A3 E8006A02              | mov     dword ptr ds:[0x26A00E8], eax                          |
004E03E9 | C3                       | ret                                                            |
```

Per the diagram above:

- **`robloxplayerbeta.025391A4`:** the memory location of the actual value of the flag. When you include a custom value for this flag in `ClientAppSettings.json`, this data gets updated to reflect the modified value.
- **`robloxplayerbeta.1F48568`:** the memory location of the constant string `"LockViolationInstanceCrash"`
- **`robloxplayerbeta.1519020`:** the next branch location after the flag name and memory address are added as function args.

Note how quickly each of these statements follow each other.

Through testing, we expect that the first two statements use the same opcode and are _immediately_ adjacent. However, the third statement may not directly precede the last two.

Different Rōblox builds will substitute:

- `mov` or `lea` in place of `push`, and
- `jmp` in place of `call`.

### 2. Determining Other Flags' Memory Locations

It is safe to assume that every FFlag that Studio initialises will jump to `robloxplayerbeta.1519020`, like in our template example. It is also safe to assume that the distance between the three aforementioned instructions remains the same between calls. Let's revisit:

```
004E03D2 | 68 A4915302              | push    robloxplayerbeta.025391A4
004E03D7 | 68 6885F401              | push    robloxplayerbeta.1F48568
004E03DC | E8 3F8C0301              | call    robloxplayerbeta.1519020
```

In our example, the offset from the memory-value-push (`robloxplayerbeta.1F48568`) to the `call` is **0xA**. The offset from the name-string instruction (`robloxplayerbeta.1F48568`) to the `call` is **0x5**. Save these for a minute.

Using x64dbg's `reffind` function, we can find all the other places where `robloxplayerbeta.1519020` is accessed.

Then, using the offsets we saved, we manually trace back.
