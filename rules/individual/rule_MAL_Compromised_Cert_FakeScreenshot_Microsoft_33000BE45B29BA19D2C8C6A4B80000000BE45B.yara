import "pe"

rule MAL_Compromised_Cert_FakeScreenshot_Microsoft_33000BE45B29BA19D2C8C6A4B80000000BE45B {
   meta:
      description         = "Detects FakeScreenshot with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-10"
      version             = "1.0"

      hash                = "a4dc7f6ca11bd07162b43f6c6804927569c97c5640b4c3c6dde0c150402a63e1"
      malware             = "FakeScreenshot"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MARQUEE AUDIO VISUAL LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:0b:e4:5b:29:ba:19:d2:c8:c6:a4:b8:00:00:00:0b:e4:5b"
      cert_thumbprint     = "b3a7719d9f0a74b15670bba12348d32ea0058d4e"
      cert_valid_from     = "2026-11-10"
      cert_valid_to       = "2026-11-13"

      country             = "IE"
      state               = "Dublin"
      locality            = "Dublin"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:0b:e4:5b:29:ba:19:d2:c8:c6:a4:b8:00:00:00:0b:e4:5b"
      )
}
