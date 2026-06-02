import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330007A2A9A2E81F1D2E3801D200000007A2A9 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-27"
      version             = "1.0"

      hash                = "5cc85f92128951bcabb7e2df82a33bac882b634d1960dd88248cf5010bc391f4"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sharp Tavyn"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:a2:a9:a2:e8:1f:1d:2e:38:01:d2:00:00:00:07:a2:a9"
      cert_thumbprint     = "B1B09F9894EE7AEF14900C0E36058C9FB4427058"
      cert_valid_from     = "2026-03-27"
      cert_valid_to       = "2026-03-30"

      country             = "US"
      state               = "Oklahoma"
      locality            = "Ringling"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:a2:a9:a2:e8:1f:1d:2e:38:01:d2:00:00:00:07:a2:a9"
      )
}
