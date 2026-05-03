import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_33000559EC04F8F0531F1F232B0000000559EC {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-18"
      version             = "1.0"

      hash                = "a7871d21014e279fe6232c744227b2112a52ec7e829c45001122e85715f6d436"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:59:ec:04:f8:f0:53:1f:1f:23:2b:00:00:00:05:59:ec"
      cert_thumbprint     = "D31348FD51332366C4903F98C6B8510F9B256660"
      cert_valid_from     = "2025-11-18"
      cert_valid_to       = "2025-11-21"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:59:ec:04:f8:f0:53:1f:1f:23:2b:00:00:00:05:59:ec"
      )
}
