import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330005D58F978A6C19F60308F100000005D58F {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-17"
      version             = "1.0"

      hash                = "c1616cab9de94e0ff962bd4ce51cd35bc465bd6ee9eea2ba328abb6ca1e7e33b"
      malware             = "Unknown"
      malware_type        = "Initial access tool"
      malware_notes       = "Flagged by Microsoft as Storm-0300 related."

      signer              = "MARKET BRIDGE HOLDINGS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:d5:8f:97:8a:6c:19:f6:03:08:f1:00:00:00:05:d5:8f"
      cert_thumbprint     = "DC5383549726F60F9F437B7157EAAEDA251A11FA"
      cert_valid_from     = "2025-12-17"
      cert_valid_to       = "2025-12-20"

      country             = "GB"
      state               = "Greater London"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:d5:8f:97:8a:6c:19:f6:03:08:f1:00:00:00:05:d5:8f"
      )
}
