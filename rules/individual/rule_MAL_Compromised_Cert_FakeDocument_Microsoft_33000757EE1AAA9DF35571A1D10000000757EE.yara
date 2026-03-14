import "pe"

rule MAL_Compromised_Cert_FakeDocument_Microsoft_33000757EE1AAA9DF35571A1D10000000757EE {
   meta:
      description         = "Detects FakeDocument with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-09"
      version             = "1.0"

      hash                = "bbb212bc7b91797f7354ea34ca502188cf270bb57f14dc4b4ab09585ff768847"
      malware             = "FakeDocument"
      malware_type        = "Initial access tool"
      malware_notes       = "The file is a fake PDF that loads an embedded photo of a passport."

      signer              = "KATELYN KELTON"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:57:ee:1a:aa:9d:f3:55:71:a1:d1:00:00:00:07:57:ee"
      cert_thumbprint     = "6B30444979C52BBE2026156DE10E134BD5FDD57D"
      cert_valid_from     = "2026-03-09"
      cert_valid_to       = "2026-03-12"

      country             = "US"
      state               = "Indiana"
      locality            = "JEFFERSONVILLE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:57:ee:1a:aa:9d:f3:55:71:a1:d1:00:00:00:07:57:ee"
      )
}
