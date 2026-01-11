import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330007058C9AC84237BBAFF51F00000007058C {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-09"
      version             = "1.0"

      hash                = "dad515ffd0ed9d6181220893edb32245e9477a1c297b4084590986f126818b5f"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Market Intelligence Systems (MIS) B.V."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:05:8c:9a:c8:42:37:bb:af:f5:1f:00:00:00:07:05:8c"
      cert_thumbprint     = "9A4DDF9F3041A8A07D13B361F9B5C81E058B49E6"
      cert_valid_from     = "2026-01-09"
      cert_valid_to       = "2026-01-12"

      country             = "NL"
      state               = "Zuid-Holland"
      locality            = "Dordrecht"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:05:8c:9a:c8:42:37:bb:af:f5:1f:00:00:00:07:05:8c"
      )
}
