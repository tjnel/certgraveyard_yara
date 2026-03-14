import "pe"

rule MAL_Compromised_Cert_FakeNSFW2_Microsoft_3300080D2103A19D93ADFED776000000080D21 {
   meta:
      description         = "Detects FakeNSFW2 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-09"
      version             = "1.0"

      hash                = "084c4628027cd8896bc9144f36388739f98577f38f0bace678dc03a6d3db75b1"
      malware             = "FakeNSFW2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Jacob Garrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:0d:21:03:a1:9d:93:ad:fe:d7:76:00:00:00:08:0d:21"
      cert_thumbprint     = "C26337FF9A6A9322B20F546D7D1D1EED5D325F3B"
      cert_valid_from     = "2026-03-09"
      cert_valid_to       = "2026-03-12"

      country             = "US"
      state               = "Mississippi"
      locality            = "Blue Springs"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:0d:21:03:a1:9d:93:ad:fe:d7:76:00:00:00:08:0d:21"
      )
}
