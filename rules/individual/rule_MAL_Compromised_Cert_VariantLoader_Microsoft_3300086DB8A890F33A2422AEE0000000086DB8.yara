import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_3300086DB8A890F33A2422AEE0000000086DB8 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-15"
      version             = "1.0"

      hash                = "8cfeb26253cfd08f252058689556f21764078afe77ddcf79d4538e0ddf5d6e51"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 188.137.246.189"

      signer              = "DIGITAL ADVERTISING BUSINESS INFLUENCERS S.R.L."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:6d:b8:a8:90:f3:3a:24:22:ae:e0:00:00:00:08:6d:b8"
      cert_thumbprint     = "2E4833B716A7B56DE54FDEEF1E0814EAD26B9E31"
      cert_valid_from     = "2026-03-15"
      cert_valid_to       = "2026-03-18"

      country             = "RO"
      state               = "Brasov"
      locality            = "Brasov"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:6d:b8:a8:90:f3:3a:24:22:ae:e0:00:00:00:08:6d:b8"
      )
}
