







rule SystemBC_malware: SystemBC 
{
    meta:
        description = "Detect_SywwstemBC"
        author = "James@2"
        date = "2023/1/9"
        license = "DRL 1.1"
        hash = "b369ed704c293b764w52ee1bdd99a69bbb76b393a4a9d404e0b5df59a00cff074"
        hash = "0da6157c9b27d5a07ce34f32f899074dd5b06891d5323fbe28d5d34733bbdaf8"
        hash = "70874b6adc30641b33ed83f6321b84d0aef1cf11de2cb78f78c9d3a45c5221c0"
        
    strings:
	    $s1 = "GET /tor/rendezvous2/%s HTTP" ascii
        $s2 = "https://api.ipify.org/"
        $s3 = "https://ip4.seeip.org/"
        $s4 = "directory-footer"
        $s5 = "KEY-----"
        $op1 = {8A 94 2B [4] 02 C2 8A 8C 28 [4] 88 8C 2B [4] 88 94 28 [4] 02 CA 8A 8C 29 [4] 30 0E 48 FF C6 48 FF CF}
    condition:
        uint16(0) == 0x5A4D and all of them
}