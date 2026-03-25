import "pe"

rule MAL_Compromised_Cert_FakeMSTeams_Microsoft_3300086D150E4B7148FEAEE9E3000000086D15 {
   meta:
      description         = "Detects FakeMSTeams with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "18c5b7a39be2f4a4b2fd45f0f273874f5efcc8751d4e592e5f2bcf6dbf781277"
      malware             = "FakeMSTeams"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tryphena Lewis"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:6d:15:0e:4b:71:48:fe:ae:e9:e3:00:00:00:08:6d:15"
      cert_thumbprint     = "E31140FFB2C78F372829300514705FB5C3E0EB56"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2026-03-26"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:6d:15:0e:4b:71:48:fe:ae:e9:e3:00:00:00:08:6d:15"
      )
}
