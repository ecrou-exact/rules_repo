rule test {
	condition:
	1
}

rule tete{
	conditi
}

rule Detect_lumma_stealer: lumma
{
    meta:
    
        description = "Detect_lumma_stealer"
        author = "James@2"
        date = "2023/1/7"
        license = "DRL 1.1"
        hash = "61b9701ec94779c40f9b6d54faf9683456d02e0ee921adbb698bf1fee8b11ce8"
        hash = "277d7f450268aeb4e7fe942f70a9df63aa429d703e9400370f0621a438e918bf"
        hash = "9b742a890aff9c7a2b54b620fe5e1fcfa553648695d79c892564de09b850c92b"
        hash = "60247d4ddd08204818b60ade4bfc32d6c31756c574a5fe2cd521381385a0f868"
                
   
         
        $s1 = "- PC:" ascii 
        $s2 = "- User:" ascii
        $s3 =
        $s4 = "- Language:" ascii
        
        $op = {0B C8 69 F6 [4] 0F B6 47 ?? C1 E1 ?? 0B C8 0F B6 07 C1 E1 ?? 83 C7 ?? 0B C8 69 C9 [4] 8B C1 C1 E8 ?? 33 C1 69 C8 [4] 33 F1}

    condition:
        uint16(0) == 0x5A4D and $op and all of ($s*)
}

rule Linux_DirtyCow_Exploit {
   meta:
      description = "Detects Linux Dirty Cow Exploit - CVE-2012-0056 and CVE-2016-5195"
      author = "Florian Roth"
      reference = "http://dirtycow.ninja/"
      date = "2016-10-21"
   strings:
      $a1 = { 48 89 D6 41 B9 00 00 00 00 41 89 C0 B9 02 00 00 00 BA 01 00 00 00 BF 00 00 00 00 }

      $b1 = { E8 ?? FC FF FF 48 8B 45 E8 BE 00 00 00 00 48 89 C7 E8 ?? FC FF FF 48 8B 45 F0 BE 00 00 00 00 48 89 }
      $b2 = { E8 ?? FC FF FF B8 00 00 00 00 }

      $source1 = "madvise(map,100,MADV_DONTNEED);"
      $source2 = "=open(\"/proc/self/mem\",O_RDWR);"
      $source3 = ",map,SEEK_SET);"

      $source_printf1 = "mmap %x"
      $source_printf2 = "procselfmem %d"
      $source_printf3 = "madvise %d"
      $source_printf4 = "[-] failed to patch payload"
      $source_printf5 = "[-] failed to win race condition..."
      $source_printf6 = "[*] waiting for reverse connect shell..."

      $s1 = "/proc/self/mem"
      $s2 = "/proc/%d/mem"
      $s3 = "/proc/self/map"
      $s4 = "/proc/%d/map"

      $p1 = "pthread_create" fullword ascii
      $p2 = "pthread_join" fullword ascii
   condition:
      ( uint16(0) == 0x457f and $a1 ) or
      all of ($b*) or
      3 of ($source*) or
      ( uint16(0) == 0x457f and 1 of ($s*) and all of ($p*) and filesize < 20KB )
}

import "pe"

rule clean_apt15_patchedcmd{
	meta:
		author = "Ahmed Zaki"
		description = "This is a patched CMD. This is the CMD that RoyalCli uses."
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		sha256 = "90d1f65cfa51da07e040e066d4409dc8a48c1ab451542c894a623bc75c14bf8f"
	strings:
	    $ = "eisableCMD" wide
	    $ = "%WINDOWS_COPYRIGHT%" wide
	    $ = "Cmd.Exe" wide
	    $ = "Windows Command Processor" wide
	condition:
        	all of them
}

rule malware_apt15_royalcli_1{
	meta:
    description = "Generic strings found in the Royal CLI tool"
    reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		author = "David Cannings"
		sha256 = "6df9b712ff56009810c4000a0ad47e41b7a6183b69416251e060b5c80cd05785"

	strings:
	    $ = "%s~clitemp%08x.tmp" fullword
	    $ = "qg.tmp" fullword
	    $ = "%s /c %s>%s" fullword
	    $ = "hkcmd.exe" fullword
	    $ = "%snewcmd.exe" fullword
	    $ = "%shkcmd.exe" fullword
	    $ = "%s~clitemp%08x.ini" fullword
	    $ = "myRObject" fullword
	    $ = "myWObject" fullword
	    $ = "10 %d %x\x0D\x0A"
	    $ = "4 %s  %d\x0D\x0A"
	    $ = "6 %s  %d\x0D\x0A"
	    $ = "1 %s  %d\x0D\x0A"
	    $ = "3 %s  %d\x0D\x0A"
	    $ = "5 %s  %d\x0D\x0A"
	    $ = "2 %s  %d 0 %d\x0D\x0A"
	    $ = "2 %s  %d 1 %d\x0D\x0A"
	    $ = "%s file not exist" fullword

	condition:
	    5 of them
}

rule malware_apt15_royalcli_2{
	meta:
    author = "Nikolaos Pantazopoulos"
    description = "APT15 RoyalCli backdoor"
    reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
		$string1 = "%shkcmd.exe" fullword
		$string2 = "myRObject" fullword
		$string3 = "%snewcmd.exe" fullword
		$string4 = "%s~clitemp%08x.tmp" fullword
		$string5 = "hkcmd.exe" fullword
		$string6 = "myWObject" fullword
	condition:
		uint16(0) == 0x5A4D and 2 of them
}

rule malware_apt15_royaldll{
	meta:
		author = "David Cannings"
		description = "DLL implant, originally rights.dll and runs as a service"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
		sha256 = "bc937f6e958b339f6925023bc2af375d669084e9551fd3753e501ef26e36b39d"          
	strings:
	    /*
	      56                push    esi
	      B8 A7 C6 67 4E    mov     eax, 4E67C6A7h
	      83 C1 02          add     ecx, 2
	      BA 04 00 00 00    mov     edx, 4
	      57                push    edi
	      90                nop
	    */
	    // JSHash implementation (Justin Sobel's hash algorithm)
		$opcodes_jshash = { B8 A7 C6 67 4E 83 C1 02 BA 04 00 00 00 57 90 }

	    /*
	      0F B6 1C 03       movzx   ebx, byte ptr [ebx+eax]
	      8B 55 08          mov     edx, [ebp+arg_0]
	      30 1C 17          xor     [edi+edx], bl
	      47                inc     edi
	      3B 7D 0C          cmp     edi, [ebp+arg_4]
	      72 A4             jb      short loc_10003F31
	    */
	    // Encode loop, used to "encrypt" data before DNS request
		$opcodes_encode = { 0F B6 1C 03 8B 55 08 30 1C 17 47 3B 7D 0C }

	    /*
	      68 88 13 00 00    push    5000 # Also seen 3000, included below
	      FF D6             call    esi ; Sleep
	      4F                dec     edi
	      75 F6             jnz     short loc_10001554
	    */
	    // Sleep loop
		$opcodes_sleep_loop = { 68 (88|B8) (13|0B) 00 00 FF D6 4F 75 F6 }

	    // Generic strings
	    $ = "Nwsapagent" fullword
	    $ = "\"%s\">>\"%s\"\\s.txt"
	    $ = "myWObject" fullword
	    $ = "del c:\\windows\\temp\\r.exe /f /q"
	    $ = "del c:\\windows\\temp\\r.ini /f /q"
	condition:
		3 of them
}


rule malware_apt15_exchange_tool {
	meta:
		author = "Ahmed Zaki"
		md5 = "d21a7e349e796064ce10f2f6ede31c71"
		description = "This is a an exchange enumeration/hijacking tool used by an APT 15"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
		$s1= "subjectname" fullword
		$s2= "sendername" fullword
		$s3= "WebCredentials" fullword
		$s4= "ExchangeVersion"	fullword
		$s5= "ExchangeCredentials"	fullword
		$s6= "slfilename"	fullword
		$s7= "EnumMail"	fullword
		$s8= "EnumFolder"	fullword
		$s9= "set_Credentials"	fullword
		$s10 = "/de" wide
		$s11 = "/sn" wide
		$s12 = "/sbn" wide
		$s13 = "/list" wide
		$s14 = "/enum" wide
		$s15 = "/save" wide
		 = "/ao" wide
		$s17 = "/sl" wide
		$s18 = "/v or /t is null" wide
		$s19 = "2007" wide
		$s20 = "2010" wide
		$s21 = "2010sp1" wide
		$s22 = "2010sp2" wide
		$s23 = "2013" wide
		$s24 = "2013sp1" wide
	condition:
		uint16(0) == 0x5A4D and 15 of ($s*)
}

rule malware_apt15_generic {
	meta:
		author = "David Cannings"
		description = "Find generic data potentially relating to AP15 tools"
		reference = "https://www.nccgroup.trust/us/about-us/newsroom-and-events/blog/2018/march/apt15-is-alive-and-strong-an-analysis-of-royalcli-and-royaldns/"
	strings:
	    // Appears to be from copy/paste code
		$str01 = "myWObject" fullword
		$str02 = "myRObject" fullword

	    /*
	      6A 02             push    2               ; dwCreationDisposition
	      6A 00             push    0               ; lpSecurityAttributes
	      6A 00             push    0               ; dwShareMode
	      68 00 00 00 C0    push    0C0000000h      ; dwDesiredAccess
	      50                push    eax             ; lpFileName
	      FF 15 44 F0 00 10 call    ds:CreateFileA
	    */
	    // Arguments for CreateFileA
		$opcodes01 = { 6A (02|03) 6A 00 6A 00 68 00 00 00 C0 50 FF 15 }
  	condition:
		2 of them
}
