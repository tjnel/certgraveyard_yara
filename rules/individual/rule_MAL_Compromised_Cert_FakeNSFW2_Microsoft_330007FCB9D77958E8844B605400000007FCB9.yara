import "pe"

rule MAL_Compromised_Cert_FakeNSFW2_Microsoft_330007FCB9D77958E8844B605400000007FCB9 {
   meta:
      description         = "Detects FakeNSFW2 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-06"
      version             = "1.0"

      hash                = "0c680e59a5ce447ba02a45526afa3f1dd735fa0e8b9a1eebab1dde69bdd2e9e7"
      malware             = "FakeNSFW2"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ricardo Reis"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:07:fc:b9:d7:79:58:e8:84:4b:60:54:00:00:00:07:fc:b9"
      cert_thumbprint     = "F24D53BBE8E2B80A6094CC91C89C7B501B867878"
      cert_valid_from     = "2026-03-06"
      cert_valid_to       = "2026-03-09"

      country             = "US"
      state               = "South Carolina"
      locality            = "Johnston"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:07:fc:b9:d7:79:58:e8:84:4b:60:54:00:00:00:07:fc:b9"
      )
}
