import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_3300082A8BABA70A0B83E0CC71000000082A8B {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-04"
      version             = "1.0"

      hash                = "e7f89e6b4d98cba833a8c7c607626c2f0d3eb7a831bf8ab053b95e29b3970818"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "Trojanized game installers. Detonation -> https://app.any.run/tasks/b573136d-3902-4c14-91b6-e38def28e96f"

      signer              = "Ricardo Reis"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:2a:8b:ab:a7:0a:0b:83:e0:cc:71:00:00:00:08:2a:8b"
      cert_thumbprint     = "F72C3C4F77BE4081F8791710260F5332D709612B"
      cert_valid_from     = "2026-03-04"
      cert_valid_to       = "2026-03-07"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:2a:8b:ab:a7:0a:0b:83:e0:cc:71:00:00:00:08:2a:8b"
      )
}
