import "pe"

rule MAL_Compromised_Cert_FakeDocument_Microsoft_330008B41662C4BC6792517D3700000008B416 {
   meta:
      description         = "Detects FakeDocument with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-25"
      version             = "1.0"

      hash                = "fc63fadddbf57ad0e18fbf69e2c98c75451d408325c629166cfed5b1aa6f6d5e"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = "The file is a fake PDF that loads an embedded photo of a ID."

      signer              = "Eliezer Valentin"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:b4:16:62:c4:bc:67:92:51:7d:37:00:00:00:08:b4:16"
      cert_thumbprint     = "ADAE323841F8C6DC1AABAB4B3FB4E17724628EFA"
      cert_valid_from     = "2026-03-25"
      cert_valid_to       = "2026-03-28"

      country             = "US"
      state               = "Texas"
      locality            = "CEDAR HILL"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:b4:16:62:c4:bc:67:92:51:7d:37:00:00:00:08:b4:16"
      )
}
