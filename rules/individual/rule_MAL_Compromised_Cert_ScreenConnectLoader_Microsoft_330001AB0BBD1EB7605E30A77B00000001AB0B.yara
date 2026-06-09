import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001AB0BBD1EB7605E30A77B00000001AB0B {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-03"
      version             = "1.0"

      hash                = "8ec59d86edfbbcf75d452aba92f28b95e07cce102fedfa9f63bbe73a51bab170"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Danielle Hale"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:ab:0b:bd:1e:b7:60:5e:30:a7:7b:00:00:00:01:ab:0b"
      cert_thumbprint     = "0AE8AC4E9509B199E2B2787387C9104D171209D7"
      cert_valid_from     = "2026-06-03"
      cert_valid_to       = "2026-06-06"

      country             = "US"
      state               = "oh"
      locality            = "Cleveland"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:ab:0b:bd:1e:b7:60:5e:30:a7:7b:00:00:00:01:ab:0b"
      )
}
