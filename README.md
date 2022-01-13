// 	run with -sgr flags / best results when forensic image is mounted

rule find_wavebrowser
{					
	meta:
		author = "Saulo 'Sal' Ortiz, Sr. Cyber Forensics Analyst"
		description = "To scan for WaveBrowser indicators"
    reference = ""
		date = "2021-12-11"
		updated = "2021-12-22"
		in_the_wild = "True"
						
// Can be used in text "string" or pearl language format /\string/.
// You can also add a file format as /\string.exe/ or as /\string\.exe/

	strings:
		$a1 = /\wavebrowser/ 
		$a2 = /\SWUpdater/ 
		$a3 = /\wavesor/ 
		$a4 = /\webexe (1)/
		
		//$re1 = /md5: [0-9a-fA-F]{32}/
		//$re2 = /state: (on|off)/
		
		$hex1 = { ad b1 28 81 e9 d0 }		// webexe (1).exe
		$hex2 = { 81 d1 26 c4 c5 b0 }			// inetc.dll	
		$hex3 = { 78 5c 72 74 66 31 }			// info.dll
		$hex4 = { 71 5c d7 e1 35 3d }			// nsArray.dll
		$hex5 = { 7c 2e 0e 63 38 4f }			// nsDialogs.dll
		$hex6 = { 1d d6 28 75 59 b7 }			// nsResize.dll
		$hex7 = { 69 72 2a 92 2d 13 } 			// System.dll
		$hex8 = { ac fe 61 08 e8 9f }			// SWUpdaterSetup.exe
		$hex9 = { 53 57 55 70 64 61 }				// SWUpdater.exe
		$hex10 = { 7d f5 e5 7e 39 94 }					// psmachine.dll	
		$hex11 = { dc 31 06 2f 98 50 }					// psmachine_64.dll
		$hex12 = { 7d f5 e5 7e 39 94 } 					// puser.dll
		$hex13 = { dc 31 06 2f 98 50 }					// puser_64.dll
		$hex14 = { d3 ec 11 d3 97 8d }					// swupdater.dll 
		$hex15 = { 89 45 ae c7 cd 24 }					// SWUpdater.exe
		$hex16 = { ba 35 f9 3d fe 54 }					// SWUpdaterBroker.exe
		$hex17 = { f7 14 5c 29 b3 75 }					// SWUpdaterComRegisterShell64.exe
		$hex18 = { 5d 0b b6 dd 19 6a }					// SWUpdaterCore.exe
		$hex19 = { ce 33 e4 21 8a 52 }					// SWUpdaterCrashHandler.exe
		$hex20 = { 12 1f a2 6c 56 7e }					// SWUpdaterCrashHandler64.exe
		$hex21 = { ba 35 f9 3d fe 54 }					// SWUpdaterOnDemand.exe
		$hex22 = { f5 42 2e ea b1 23 }					// swupdaterres_en.dll
 				
	condition:
		any of ($a*) or any of ($hex*)
