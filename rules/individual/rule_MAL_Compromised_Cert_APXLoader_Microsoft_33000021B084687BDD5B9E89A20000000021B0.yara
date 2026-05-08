import "pe"

rule MAL_Compromised_Cert_APXLoader_Microsoft_33000021B084687BDD5B9E89A20000000021B0 {
   meta:
      description         = "Detects APXLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-09"
      version             = "1.0"

      hash                = "abc14ea855a5d5bb17d965f377e791280939de147afde1f08ec2ea2da97fe31d"
      malware             = "APXLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "Vic Thadhani"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:21:b0:84:68:7b:dd:5b:9e:89:a2:00:00:00:00:21:b0"
      cert_thumbprint     = "945614CA0D89E59D38EF73F56A4A8A56CA679D1B"
      cert_valid_from     = "2026-04-09"
      cert_valid_to       = "2026-04-12"

      country             = "US"
      state               = "California"
      locality            = "PALO ALTO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:21:b0:84:68:7b:dd:5b:9e:89:a2:00:00:00:00:21:b0"
      )
}
