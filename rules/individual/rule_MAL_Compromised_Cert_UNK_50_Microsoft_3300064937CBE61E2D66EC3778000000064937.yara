import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300064937CBE61E2D66EC3778000000064937 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-08"
      version             = "1.0"

      hash                = "5ceb78fd5d675779df1f81f50abb43eaae3d8bff2f4d3161c6778f6d656cc70f"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Market Intelligence Systems (MIS) B.V."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:06:49:37:cb:e6:1e:2d:66:ec:37:78:00:00:00:06:49:37"
      cert_thumbprint     = "5AD607D097A6E66CC75DA9ADD0AFF795D026C92A"
      cert_valid_from     = "2026-01-08"
      cert_valid_to       = "2026-01-11"

      country             = "NL"
      state               = "Zuid-Holland"
      locality            = "Dordrecht"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:06:49:37:cb:e6:1e:2d:66:ec:37:78:00:00:00:06:49:37"
      )
}
