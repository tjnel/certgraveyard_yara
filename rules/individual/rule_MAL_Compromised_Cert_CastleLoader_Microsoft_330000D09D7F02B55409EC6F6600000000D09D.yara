import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330000D09D7F02B55409EC6F6600000000D09D {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-08"
      version             = "1.0"

      hash                = "f0c01e8b424f092d1df409ce1f4d29b0674eaa2ecd346ea1bbd6889573a38d16"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: elvaronexkas[.]com"

      signer              = "Slims Software"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:d0:9d:7f:02:b5:54:09:ec:6f:66:00:00:00:00:d0:9d"
      cert_thumbprint     = "C0A9D5C2EFAD96BFBD182C426406452994A1A6D1"
      cert_valid_from     = "2026-05-08"
      cert_valid_to       = "2026-05-11"

      country             = "NL"
      state               = "Utrecht"
      locality            = "Utrecht"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:d0:9d:7f:02:b5:54:09:ec:6f:66:00:00:00:00:d0:9d"
      )
}
