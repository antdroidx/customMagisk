from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path('.')

def read(rel):
    return (root / rel).read_text()

def write(rel, text):
    (root / rel).write_text(text)

def replace_required(text, old, new, label):
    if old not in text:
        print(f"WARNING: did not find {label}")
        return text
    return text.replace(old, new, 1)

# Memory: expose full 128MB and force extra-memory mode on.
rel = 'pcsx2/Memory.cpp'
s = read(rel)
s = s.replace('u32 ExposedRam = MainRam;', 'u32 ExposedRam = TotalRam;')
s = s.replace('u32 ExposedIopRam = IopRam;', 'u32 ExposedIopRam = TotalIopRam;')
s = s.replace('static bool s_extra_memory = false;', 'static bool s_extra_memory = true;')
if 'hard-forcing EE interpreter and fastmem off before memory allocation' not in s:
    s = replace_required(
        s,
        'DevCon.WriteLn(Color_StrongBlue, "Allocating host memory for virtual systems...");\n\n',
        'DevCon.WriteLn(Color_StrongBlue, "Allocating host memory for virtual systems...");\n\n'
        '#if defined(ARCH_ARM64)\n'
        '\tEmuConfig.Cpu.Recompiler.EnableEE = false;\n'
        '\tEmuConfig.Cpu.Recompiler.EnableFastmem = false;\n'
        '\tConsole.Warning("NCAA 128MB Android test: hard-forcing EE interpreter and fastmem off before memory allocation.");\n'
        '#endif\n\n',
        'Memory.cpp allocation hook',
    )
arm_guard_old = '''\tif (mode && EmuConfig.Cpu.Recompiler.EnableEE)
\t{
\t\tConsole.Warning("Extended RAM (128MB) is not supported by the ARM64 EE recompiler; ignoring it. "
\t\t\t\t\t\t"Disable the EE recompiler if you need it.");
\t\tmode = false;
\t}
'''
arm_guard_new = '''\tif (mode && EmuConfig.Cpu.Recompiler.EnableEE)
\t{
\t\tEmuConfig.Cpu.Recompiler.EnableEE = false;
\t\tEmuConfig.Cpu.Recompiler.EnableFastmem = false;
\t\tConsole.Warning("NCAA 128MB Android test: forcing EE interpreter because ARM64 EE recompiler is MainRam-only.");
\t}
'''
s = s.replace(arm_guard_old, arm_guard_new)
write(rel, s)

# R5900: map the extra 96MB and mirrors during EELOAD.
rel = 'pcsx2/R5900.cpp'
s = read(rel)
if '#include "Memory.h"' not in s:
    s = s.replace('#include "R5900.h"\n', '#include "R5900.h"\n#include "Memory.h"\n#include "vtlb.h"\n')
if 'mapping extra EE RAM in eeloadHook' not in s:
    s = replace_required(
        s,
        '\tVMManager::Internal::ELFLoadingOnCPUThread(std::move(elfname));\n\n',
        '\tVMManager::Internal::ELFLoadingOnCPUThread(std::move(elfname));\n\n'
        '\tif (memGetExtraMemMode())\n'
        '\t{\n'
        '\t\tConsole.Warning("NCAA 128MB Android test: mapping extra EE RAM in eeloadHook.");\n'
        '\t\tvtlb_VMap(Ps2MemSize::MainRam, Ps2MemSize::MainRam, Ps2MemSize::ExtraRam);\n'
        '\t\tvtlb_VMap(0x20000000 | Ps2MemSize::MainRam, Ps2MemSize::MainRam, Ps2MemSize::ExtraRam);\n'
        '\t\tvtlb_VMap(0x30000000 | Ps2MemSize::MainRam, Ps2MemSize::MainRam, Ps2MemSize::ExtraRam);\n'
        '\t}\n\n',
        'R5900.cpp eeloadHook map',
    )
write(rel, s)

# BIOS syscalls: report extended memory to the game.
rel = 'pcsx2/R5900OpcodeImpl.cpp'
s = read(rel)
if '#include "Memory.h"' not in s:
    s = s.replace('#include "R5900.h"\n', '#include "R5900.h"\n#include "Memory.h"\n')
if 'HLE RFU060 memory query' not in s:
    s = replace_required(
        s,
        '\t\tcase Syscall::SetOsdConfigParam:\n',
        '\t\tcase Syscall::RFU060:\n'
        '\t\t\tif (memGetExtraMemMode() && cpuRegs.GPR.n.a1.UL[0] == 0xFFFFFFFF)\n'
        '\t\t\t{\n'
        '\t\t\t\tConsole.Warning("NCAA 128MB Android test: HLE RFU060 memory query.");\n'
        '\t\t\t\tcpuRegs.GPR.n.a1.UL[0] = Ps2MemSize::ExposedRam - cpuRegs.GPR.n.a2.SL[0];\n'
        '\t\t\t}\n'
        '\t\t\tbreak;\n'
        '\t\tcase Syscall::SetOsdConfigParam:\n',
        'RFU060 syscall',
    )
if 'HLE GetMemorySize -> ExposedRam' not in s:
    s = replace_required(
        s,
        '\n\n\t\tdefault:\n',
        '\n\t\tcase Syscall::GetMemorySize:\n'
        '\t\t\tif (memGetExtraMemMode())\n'
        '\t\t\t{\n'
        '\t\t\t\tConsole.Warning("NCAA 128MB Android test: HLE GetMemorySize -> ExposedRam.");\n'
        '\t\t\t\tcpuRegs.GPR.n.v0.UL[0] = Ps2MemSize::ExposedRam;\n'
        '\t\t\t\treturn;\n'
        '\t\t\t}\n'
        '\t\t\tbreak;\n\n'
        '\t\tdefault:\n',
        'GetMemorySize syscall',
    )
write(rel, s)

# VMManager: Android/settings re-applied ee_rec=1 last time. Force it off at each CPU settings/update stage.
rel = 'pcsx2/VMManager.cpp'
s = read(rel)
block_template = '''#if defined(ARCH_ARM64)
\tEmuConfig.Cpu.Recompiler.EnableEE = false;
\tEmuConfig.Cpu.Recompiler.EnableFastmem = false;
\tConsole.Warning("NCAA 128MB Android test: hard-forcing EE interpreter and fastmem off in {where}.");
#endif
'''

def inject_func(src, func, where):
    marker = f'hard-forcing EE interpreter and fastmem off in {where}'
    if marker in src:
        return src
    pat = r'(void VMManager::' + re.escape(func) + r'\([^)]*\)\s*\{\n)'
    block = block_template.format(where=where)
    new, n = re.subn(pat, lambda m: m.group(1) + block, src, count=1)
    if n == 0:
        print(f"WARNING: did not find VMManager::{func}")
    return new

for func in ['ApplyCoreSettings', 'UpdateCPUImplementations', 'CheckForCPUConfigChanges', 'ClampRuntimeConfigToAvailableCPUProviders']:
    s = inject_func(s, func, f'VMManager::{func}')

if 'hard-forcing EE interpreter and fastmem off before Updating CPU configuration log' not in s:
    s = s.replace(
        'Console.WriteLn("Updating CPU configuration...");\n',
        'Console.WriteLn("Updating CPU configuration...");\n'
        '#if defined(ARCH_ARM64)\n'
        '\tEmuConfig.Cpu.Recompiler.EnableEE = false;\n'
        '\tEmuConfig.Cpu.Recompiler.EnableFastmem = false;\n'
        '\tConsole.Warning("NCAA 128MB Android test: hard-forcing EE interpreter and fastmem off before Updating CPU configuration log.");\n'
        '#endif\n',
        1,
    )
write(rel, s)

subprocess.run('grep -R "NCAA 128MB Android test" -n pcsx2 || true', shell=True, check=True)
