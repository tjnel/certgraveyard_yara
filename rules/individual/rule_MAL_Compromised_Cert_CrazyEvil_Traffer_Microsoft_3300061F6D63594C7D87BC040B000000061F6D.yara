import "pe"

rule MAL_Compromised_Cert_CrazyEvil_Traffer_Microsoft_3300061F6D63594C7D87BC040B000000061F6D {
   meta:
      description         = "Detects CrazyEvil Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-31"
      version             = "1.0"

      hash                = "9507ce7534cf31314fb38535e85231fa63d603ce68cabeaaf8a4b0020ac91aa4"
      malware             = "CrazyEvil Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SOFTOLIO sp. z o.o."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:06:1f:6d:63:59:4c:7d:87:bc:04:0b:00:00:00:06:1f:6d"
      cert_thumbprint     = ""
      cert_valid_from     = "2025-12-31"
      cert_valid_to       = "2026-01-03"

      country             = "PL"
      state               = "Pomorskie"
      locality            = "GDYNIA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:06:1f:6d:63:59:4c:7d:87:bc:04:0b:00:00:00:06:1f:6d"
      )
}
