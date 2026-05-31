import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_33000121F2301080A346D228410000000121F2 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-18"
      version             = "1.0"

      hash                = "88f63b49438e96b166104b7f0ce3de92b3910099fa0d12798682c13f6eb4fb5b"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Zeebodem Agro"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:21:f2:30:10:80:a3:46:d2:28:41:00:00:00:01:21:f2"
      cert_thumbprint     = "1328ED5C1E6F1F768F81D1C1D476968B1B5C8FEE"
      cert_valid_from     = "2026-05-18"
      cert_valid_to       = "2026-05-21"

      country             = "NL"
      state               = "Flevoland"
      locality            = "Swifterbant"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:21:f2:30:10:80:a3:46:d2:28:41:00:00:00:01:21:f2"
      )
}
