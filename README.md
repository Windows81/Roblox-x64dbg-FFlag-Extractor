# Rōblox FFlag Collector (ft. x64dbg)

**This tool requires the use of [the `x64dbg_automate` plugin](https://github.com/dariushoule/x64dbg-automate) for `x64dbg` and for `x64dbg` to be accessible via your `PATH`.**

---

All addresses are stored as RVAs (relative virtual addresses) to account for ASLR (address-space randomisation). In fact, x64dbg's patch format `.1337` also uses RVAs.

The fast-variables' data is stored within the following fields:

- `load`: the RVA of the static data to store the flag's default value if it isn't loaded either remotely from an HTTP request or locally in the client-settings `json` file.
- **`mem_val`**: the RVA of the memory that gets used elsewhere in Rōblox executables to load the value of the flag.
- `mem_name`: the RVA of the static in-memory _string_ that comprises the _name_ of the flag.

Here's an example run:

```ps
python main.py "c:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Studio\RobloxStudioBeta.exe" -df -ds > "./test-studio-v463.json"
```

This program is optimised for different versions of Rōblox Studio. Both 32- and 64-bit builds work.

For example, v463 exposes `DFFlagTheseAreSomeOfMyBestAttributes` to enable the use of [attributes](https://create.roblox.com/docs/scripting/attributes), but `FFlagTheseAreSomeOfMyBestAttributes` (which excludes the `D` prefix) has no effect.

## JSON "Test" Files

Attached in [`./test`](./test) are some flag dumps.

I generate these files on **my machine** using the command in [`./test/test.ps1`](./test/test.ps1).

## What?

When you load Rōblox Player or Studio, Rōblox asks a remote server to fetch a JSON dictionary with *hidden* settings that Rōblox unilaterally decide for you. These variables modify the runtime behaviour of Player or Studio.

Rōblox stores these options in what we call FFlags. However, `FFlags` are just one piece of the equation. These just refer to boolean values. Rōblox also supplies other namespace prefixes, i.e. `FInt`, `FString`, and `FLog`.

In Studio *only*, any and all individual settings can be overwritten value-by-value in a file named `./ClientSettings/ClientAppSettings.json`, if such file exists. This feature was previously available in Player [until 2025](https://devforum.roblox.com/t/allowlist-for-local-client-configuration-via-fast-flags/3966569).

It is important to note that only *a small set of possible* values are supplied in the remote JSON fetch. Otherwise, Rōblox stores in-memory defaults for each in a location that I refer to as `load` in my tool's outputs.

To show the sheer number of possible `FFlag` keys, [Studio version 695 for Windows](https://github.com/Windows81/Roblox-x64dbg-FFlag-Extractor/blob/76fef5e83b23f96a28e18cbba77422e60e4c6fbb/test/v695-studio.json) contains a number of **12,936** total fast variables (`FLags`, `FInts`, `FStrings`, and `FLogs`).

```sh
curl https://github.com/Windows81/Roblox-x64dbg-FFlag-Extractor/raw/refs/heads/main/test/v695-studio.json -L | jpp "$.*~" -s | wc
```

However, [the FFlag tracker](https://github.com/MaximumADHD/Roblox-FFlag-Tracker/blob/main/PCStudioApp.json) shows that only a number of **1,584** variables are populated from Rōblox's remote servers, as of 2025-10-28.

```sh
curl https://github.com/MaximumADHD/Roblox-FFlag-Tracker/raw/refs/heads/main/PCStudioApp.json -L | jpp "$.*~" -s | wc
```

The `jpp` utility is compiled from [a fork of a JSONPath command-line tool](https://github.com/Windows81/JSONPath-CLI/tree/patch-1) that I like using.

## How?

Rōblox stores hidden options in what we call FFlags. However, `FFlags` are just one piece of the equation. These just refer to boolean values. Rōblox also supplies other namespaces, i.e. `FInt`, `FString`, and `FLog`.

When Rōblox runs, the values are loaded directly from memory addresses. My program's job is to find these memory addresses. If `--add_flag_labels` is passed in, they are stored as shortcuts the next time you open your program in x64dbg. It's nice to see:

```patch
0196FACD | 8BC8                     | mov     ecx, eax
0196FACF | 8945 EC                  | mov     dword ptr ss:[ebp - 0x14], eax
0196FAD2 | 8B10                     | mov     edx, dword ptr ds:[eax]
0196FAD4 | FF52 20                  | call    dword ptr ds:[edx + 0x20]
-0196FAD7 | 803D 101D5602 00         | cmp     byte ptr ds:[0x02561D10]
+0196FAD7 | 803D 101D5602 00         | cmp     byte ptr ds:[<FFlag::DebugAdornsDisabled>], 0x0
0196FADE | 0F85 E3000000            | jne     robloxplayerbeta.196FBC7
```

---

Throughout the years, the names of flags which are available in Rōblox consistently change. But a few remain in vogue for a long time. The following flag-name strings were selected for their presence (1) in the 2016 source-code leak and (2) included in the `.rdata` memory region in Studio v695:

- **FFlag:** `LockViolationInstanceCrash`
- **FInt:** `StreamingSafeMemWatermarkMB`
- **FString:** `FriendsOnlineUrl`
- **FLog:** `GfxClustersFull`

We _must_ know that the memory location of this string must only be referenced _once_ in the entire program. Otherwise, I would've needed to select another flag. This is because other refs would use said string for a completely different purpose, breaking program continuity.

For example, I used `DFFlag::LockViolationInstanceCrash` in finding the names and memory addresses of boolean-valued FFlags.

---

In Player v463:

```
004E03D0 | 6A 02                    | push    0x2                           |
004E03D2 | 68 A4915302              | push    robloxplayerbeta.25391A4      |
004E03D7 | 68 6885F401              | push    robloxplayerbeta.1F48568      | 1F48568:"LockViolationInstanceCrash"
004E03DC | E8 3F8C0301              | call    robloxplayerbeta.1519020      |
004E03E1 | 83C4 0C                  | add     esp, 0xC                      |
004E03E4 | A3 E8006A02              | mov     dword ptr ds:[0x26A00E8], eax |
004E03E9 | C3                       | ret                                   |
```

Per the diagram above:

- **`push 0x2`:** a signifier for the pre-prefix:
  - `0x1` for `F` (fast-)
  - `0x2` for `DF` (debug-fast-)
  - `0x3` for `SF` (synchronised-fast-)
  
- **`push robloxplayerbeta.25391A4`:** the static memory location of the value of the flag which other code references.
  - My tool saves it as `mem_val` in its outputs.
  - When you include a custom value for this flag in `ClientAppSettings.json`, this data gets updated to reflect the modified value.
  
- **`push robloxplayerbeta.1F48568`:** the static memory location of the constant string `"LockViolationInstanceCrash"`.
  - My tool saves it as `mem_name` in its outputs.

- **`push robloxplayerbeta.1519020`:** the next branch location after the variable's name and memory address are added as function args.
  - It is safe to assume that this code path is reserved only for *boolean* `FFlag` values.

Note how quickly each of these statements follow each other.

---

Different Rōblox builds may substitute:

- `mov` or `lea` in place of `push`, and,
- `jmp` in place of `call`.

I can account for most of these differences.

---

It is safe to assume that every *boolean* `FFlag` that Studio initialises will jump to `robloxplayerbeta.1519020`, like in our template example. It is also safe to assume that the distance between the three aforementioned instructions remains the same between calls.

Using x64dbg's `reffind` function, we can find all the *many* other places where `robloxplayerbeta.1519020` is accessed. Here is one for `FFlag::DebugAdornsDisabled`

```
005B8940 | 6A 01                    | push 0x1                           |
005B8942 | 68 101D5602              | push robloxplayerbeta.2561D10      |
005B8947 | 68 D8A92902              | push robloxplayerbeta.229A9D8      | 229A9D8:"DebugAdornsDisabled"
005B894C | E8 CF06F600              | call robloxplayerbeta.1519020      |
```

Note that:
- This snippet calls `push 0x1` *instead* of `push 0x2`, and therefore,
- The corresponding key uses a `FFlag` prefix instead of `DFFlag`.
