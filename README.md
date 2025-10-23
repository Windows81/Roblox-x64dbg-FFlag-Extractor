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
