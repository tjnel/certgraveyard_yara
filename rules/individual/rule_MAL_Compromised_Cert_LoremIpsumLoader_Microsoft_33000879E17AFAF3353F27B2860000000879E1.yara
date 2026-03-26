import "pe"

rule MAL_Compromised_Cert_LoremIpsumLoader_Microsoft_33000879E17AFAF3353F27B2860000000879E1 {
   meta:
      description         = "Detects LoremIpsumLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-16"
      version             = "1.0"

      hash                = "942476cc985429f9baf40f83244f637439163eac1753eb7e740644a3b753c39b"
      malware             = "LoremIpsumLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MATTHEW PIGG"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:79:e1:7a:fa:f3:35:3f:27:b2:86:00:00:00:08:79:e1"
      cert_thumbprint     = "9C7D7693E5EECD2AAEE9DD090AD64DEB18FBB78F"
      cert_valid_from     = "2026-03-16"
      cert_valid_to       = "2026-03-19"

      country             = "US"
      state               = "California"
      locality            = "RICHMOND"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:79:e1:7a:fa:f3:35:3f:27:b2:86:00:00:00:08:79:e1"
      )
}
