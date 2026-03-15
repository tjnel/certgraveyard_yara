import "pe"

rule MAL_Compromised_Cert_FakeNDASign_Microsoft_3300084B4DB3FBEEF8CDC80160000000084B4D {
   meta:
      description         = "Detects FakeNDASign with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-11"
      version             = "1.0"

      hash                = "1096d2e220ecce73a4e7f0cdc673c2ff4f5b399693b2db5fc5dd098813633f19"
      malware             = "FakeNDASign"
      malware_type        = "Unknown"
      malware_notes       = "alware campaign targeting job-seekers with fake landing ndavia[.]com"

      signer              = "Robert Walters"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:4b:4d:b3:fb:ee:f8:cd:c8:01:60:00:00:00:08:4b:4d"
      cert_thumbprint     = "6B2132FDF9662D9635433DF4166A9DB7EC40E68C"
      cert_valid_from     = "2026-03-11"
      cert_valid_to       = "2026-03-14"

      country             = "US"
      state               = "California"
      locality            = "Placentia"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:4b:4d:b3:fb:ee:f8:cd:c8:01:60:00:00:00:08:4b:4d"
      )
}
