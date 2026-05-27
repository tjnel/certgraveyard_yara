import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000130CF5049CB9B7FF882BA0000000130CF {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-20"
      version             = "1.0"

      hash                = "9fafbc54f006ccefc3c561a8b85799cea15bfa6a6b754c4f41e7202bd06f93a4"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BEYOND TECHNOLOGIES SRL"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:30:cf:50:49:cb:9b:7f:f8:82:ba:00:00:00:01:30:cf"
      cert_thumbprint     = "5C01D716FA4B4779A47CBE75656BFE1BAF4DE40B"
      cert_valid_from     = "2026-05-20"
      cert_valid_to       = "2026-05-23"

      country             = "RO"
      state               = "Bucharest"
      locality            = "Bucuresti"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:30:cf:50:49:cb:9b:7f:f8:82:ba:00:00:00:01:30:cf"
      )
}
