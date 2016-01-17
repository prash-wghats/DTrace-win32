DTrace for windows is a port of DTrace for Windows OS. Only fasttrap
(pid provider), fbt and profile provider are ported, with varying degree of 
functionality. Use it at your own discretion.Liable to cause BSOD.So please 
dont use it on a production system.

This port is based on FreeBSD port of DTrace.Some of the functions have 
been ported from MacOS port. Non Portable(HACKS) have been mostly grouped in 
hack_i386.c & hack_amd64.c files.
 
Works best on 32 bit Windows sytem.
On 64 bit WinOS because of PatchGuard only way of testing is by attaching 
kernel debugger to the OS. If not, fasttrap.sys or fbt.sys will cause the
OS to crash!.

Windows 64 bit:
example:
Bcdedit /debug ON
Bcdedit /dbgsettings SERIAL DEBUGPORT:1 BAUDRATE:115200
Restart with kernel debugger (windbg /kd ) attached to OS.

On 64 bit system the drivers need to be signed.To the load the drivers, either 
have to enable with testing signing on (Bcdedit /TESTSIGNING ON) and install 
the test signed certificate <ContosoTest.cer> in dtrace/cert/ or start without 
requiring signed driver.The corresponding private certicate is ContosoTest.pfx.
Or you can use your own certificate and compile.

In 64 bit system to get kernel stack trace set -
HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\DisablePagingExecutive
to 1.
ex.
REG ADD "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" -v 
 		   DisablePagingExecutive -d 0x1 -t REG_DWORD -f
 		   
dtrace.exe has been compiled using gcc TDM 5.1.
In msys shell , use->  make -f Makefile.mingw  in the root directory to build everything
or you can build each modules indiviually.
For kernel drivers, in DDK (built with Windows 7 DDK) development cmd line,
use -> nmake -f Makefile.drivers 
to build all the drivers.Or you build each driver indivually using build.

DTrace kernel drivers have been compiled with win 7 DDK. Mainly tested in 
winxp SP2(32 bit) and Win7  (64 bit).

DTrace for windows uses dbghelp.dll extensively.To get Symbol information,
set _NT_SYMBOL_PATH to point to microsoft symbol server to get the pdb files 
for system dll and drivers.
example:
 SET _NT_SYMBOL_PATH=srv*c:\Symbols*http://msdl.microsoft.com/download/symbols;
	E:\prash\dtrace\bin\i386;E:\prash\dtrace\bin\amd64

if not it will use only exported functions in modules.

The DEFAULT location for dtrace library is "c:\dtrace\lib\" .This is hard coded 
in libdtrace\dt_open.c. The d script definitions (regs.d, signal.d & errno.d 
found in dtrace\lib\*) should be copied to this location.
For USDT drti.o is saved in this location, depending on the arch type. 
ie c:\dtrace\lib\<amd64\i386>\drti.o (..\<amd64\i386>\drti.o.<gcc/msvc>).

The dtrace drivers (dtrace.sys, fasttrap.sys, fbt.sys and profile.sys) have to 
be loaded to use dtrace.exe. This can be loaded using 3rd party loaders like 
OSR driver loader etc. A helper program is also provided  <dtrace_loader.exe>
which will load or unload this drivers.
 
<admintrator command prompt>
dtrace_loader.exe -l //to load dtrace drivers
dtrace_loader.exe -u //to unload dtrace drivers.

Set DTRACE_DEBUG=1 envirnoment variable, to get dtrace to give verbose 
debugging data each time it is invoked.

Dtrace Providers:
(using command prompt (cmd.exe))
profile:
ex: 	dtrace -n "profile-997 {@[stack()]=count();}"
	dtrace -n "profile-1000 {@[ustack()]=count();}"


In 64 bits, user mode stacktrace (ustack())is missing.

fbt:
IMP: Only exported functions in a driver are probed.
	dtrace -n "fbt:VBoxGuest::entry {@[probefunc]=count();}"

fasttrap.sys:
	
Since the Dtrace for windows uses dbghelp to access symbol information, 
pdb files of the program being probed should be available.While compiling 
with CL.EXE /Zi option will produce pdb symbol files. It is possible to probe 
gcc produced (does not use dwarf symbol) modules/exes as long as the symbol 
table information is present in the image file.
This seems to be the case for GCC TDM 64 5.1.
	
    dtrace -n "pid$target:loops::entry {@[ustack()]=count();}" -c loops.exe
	
You can also probe a running process using its process id. you can get this 
using tasklist.exe.
	
    dtrace -n "pid$target:kernel32::entry{@[probefunc]=count();}" -p 999
	
IMPORTANT: To use D script having preprocessor directives, GNU cpp.exe should 
be in path of DTrace. 

For USDT feature ld.exe and objcopy.exe (binutils) should be in the path.
USDT can be used with both MSVC or GCC.But drti.o will be  different.If using 
MSVC (CL.exe) to compile, then use the Makefile.drti_msvc to compile drti.o 
<requires msvc NMAKE and command line envirnment>.For gcc use 
Makefile.drti_mingw  <make> to produce the correct drti.o file.
drti.o is saved in c:\dtrace\lib\<amd64/i386>\drti.o.
