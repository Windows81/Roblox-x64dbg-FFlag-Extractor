# Rōblox FFlag Collector (ft. x64dbg)

This tool requires the use of `x64dbg_automate`, which in turn requires `x64dbg` to be in your system path.

All addresses are stored as RVAs (relative virtual addresses) to account for ASLR (address-space randomisation). In fact, x64dbg's patch format `.1337` also uses RVAs.

Here's an example run:

```ps
python main.py "c:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Studio\RobloxStudioBeta.exe" -df -ds > "./test-studio-v463.json"
```

This program is optimised for different versions of Rōblox Studio. Bitness shouldn't be a problem.

## JSON "Test" Files

Attached are some flag dumps.

[`./test-studio-v347.json`](./test-studio-v347.json) (32-bit), [`./test-studio-v410.json`](./test-studio-v410.json) (64-bit), and [`./test-studio-v463.json`](./test-studio-v463.json) (64-bit) were both generated with the `-df` and `-ds` flags.

Generations for [`./test-studio-v548.json`](./test-studio-v548.json) and [`./test-studio-v695.json`](./test-studio-v695.json) only used `-df` because string extraction is much harder to do therewith.

I generate these files on **my machine** using the following command:

```ps1
python main.py "C:\Users\USER\Downloads\0.347.0.28462 (version-d9cf1f7e4fe14aa9)\RobloxStudioBeta.exe" -df -ds > "./test/v347-studio.json" &&
python main.py "C:\Users\USER\Projects\FilteringDisabled\Roblox\v348\Server\RCCService.exe" -df -ds > "./test/v348-server.json" &&
python main.py "C:\Users\USER\Downloads\0.410.1.33582 (version-ea2cea5d307b4fe6)\RobloxStudioBeta.exe" -df -ds > "./test/v410-studio.json" &&
python main.py "C:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Studio\_RobloxStudioBeta-ORIGINAL.exe" -df -ds > "./test/v463-studio.json" &&
python main.py "C:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Player\RobloxPlayerBeta.exe" -df -ds > "./test/v463-player.json" &&
python main.py "C:\Users\USER\Projects\FilteringDisabled\Roblox\v463\Server\RCCService.exe" -df -ds > "./test/v463-server.json" &&
python main.py "F:\Users\USERNAME\AppData\Local\RobloxStudio2022\RobloxStudioBeta.exe" -df > "./test/v548-studio.json" &&
python main.py "C:\Users\USER\AppData\Local\Roblox Studio\RobloxStudioBeta.exe" -df > "./test/v695-studio.json"
```
