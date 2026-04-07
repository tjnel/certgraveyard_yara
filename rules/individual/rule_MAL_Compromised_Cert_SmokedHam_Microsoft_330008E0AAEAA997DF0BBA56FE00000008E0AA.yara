import "pe"

rule MAL_Compromised_Cert_SmokedHam_Microsoft_330008E0AAEAA997DF0BBA56FE00000008E0AA {
   meta:
      description         = "Detects SmokedHam with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "111cc2d2232705565c4dbbddf7d16104bbf83554248a2ed0520b4e37bdc3acf5"
      malware             = "SmokedHam"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "CHRISTOPHER CONLEY"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:e0:aa:ea:a9:97:df:0b:ba:56:fe:00:00:00:08:e0:aa"
      cert_thumbprint     = "9DD89FD3363F79226A5CDCB3B3F182C549822CBF"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2026-04-04"

      country             = "US"
      state               = "Alaska"
      locality            = "ANCHORAGE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:e0:aa:ea:a9:97:df:0b:ba:56:fe:00:00:00:08:e0:aa"
      )
}
