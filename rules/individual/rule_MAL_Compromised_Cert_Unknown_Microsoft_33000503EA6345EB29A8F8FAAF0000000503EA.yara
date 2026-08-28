import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_33000503EA6345EB29A8F8FAAF0000000503EA {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-18"
      version             = "1.0"

      hash                = "38f3964fac0e3d2a704b34c4a3ae5cde878ff6d994e575e6e54ed82acea7f16f"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alsace Music ApS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:05:03:ea:63:45:eb:29:a8:f8:fa:af:00:00:00:05:03:ea"
      cert_thumbprint     = "1aa815d69e7ff3af6b2e5fbe7022cfd24ed69c90"
      cert_valid_from     = "2026-08-18"
      cert_valid_to       = "2026-08-21"

      country             = "DK"
      state               = "Capital Region"
      locality            = "Kobenhavn V"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:05:03:ea:63:45:eb:29:a8:f8:fa:af:00:00:00:05:03:ea"
      )
}
