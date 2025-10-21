# Rōblox FFlag Collector (ft. x64dbg)

This tool requires the use of `x64dbg_automate`, which in turn requires `x64dbg` to be in your system path.

Here's an example run:

```ps
python main.py "c:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Studio\RobloxStudioBeta.exe" -df -ds > "./test-studio-v463.json"
```

This program is optimised for different versions of Rōblox Studio. Bitness shouldn't be a problem.

## JSON Test Files

Attached are some flag dumps. [`./test-studio-v347.json`](./test-studio-v347.json) (32-bit), [`./test-studio-v410.json`](./test-studio-v410.json) (64-bit), and [`./test-studio-v463.json`](./test-studio-v463.json) (64-bit) were both generated with the `-df` and `-ds` flags. [`./test-studio-v548.json`](./test-studio-v548.json) and [`./test-studio-v695.json`](./test-studio-v695.json) only used `-df` because string extraction is much harder to do therewith.
