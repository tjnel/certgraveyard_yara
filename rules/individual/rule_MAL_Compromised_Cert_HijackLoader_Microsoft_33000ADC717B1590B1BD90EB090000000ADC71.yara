import "pe"

rule MAL_Compromised_Cert_HijackLoader_Microsoft_33000ADC717B1590B1BD90EB090000000ADC71 {
   meta:
      description         = "Detects HijackLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-04"
      version             = "1.0"

      hash                = "dba93a0a010043b6ca620e7bd63f111359832083c14b987c6900eb6b7de1c3b3"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BG Sound"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:0a:dc:71:7b:15:90:b1:bd:90:eb:09:00:00:00:0a:dc:71"
      cert_thumbprint     = "c36416e38158eecb1014ec504e4f861e0ac3a530"
      cert_valid_from     = "2026-11-04"
      cert_valid_to       = "2026-11-07"

      country             = "NL"
      state               = "Noord-Holland"
      locality            = "Purmerend"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:0a:dc:71:7b:15:90:b1:bd:90:eb:09:00:00:00:0a:dc:71"
      )
}
