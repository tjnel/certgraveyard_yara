import "pe"

rule MAL_Compromised_Cert_ScreenConnect_Loader_Microsoft_3300031F7F74E3961CC7CBFFB1000000031F7F {
   meta:
      description         = "Detects ScreenConnect Loader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-13"
      version             = "1.0"

      hash                = "093db91d8a9c42faf74d6531eacab95e1175952a8defd0a86113ab92403e4f22"
      malware             = "ScreenConnect Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "jasmine mosby"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:03:1f:7f:74:e3:96:1c:c7:cb:ff:b1:00:00:00:03:1f:7f"
      cert_thumbprint     = "c8dc83c40a2a585dab337dfd7337b270030efa61"
      cert_valid_from     = "2026-07-13"
      cert_valid_to       = "2026-07-16"

      country             = "US"
      state               = "ar"
      locality            = "Little Rock"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:03:1f:7f:74:e3:96:1c:c7:cb:ff:b1:00:00:00:03:1f:7f"
      )
}
