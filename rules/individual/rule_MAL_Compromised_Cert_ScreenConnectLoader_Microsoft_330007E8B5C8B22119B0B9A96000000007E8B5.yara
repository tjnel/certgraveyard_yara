import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330007E8B5C8B22119B0B9A96000000007E8B5 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-06"
      version             = "1.0"

      hash                = "d569251edb7e5e3444d56a339dc4bf24f4de2378c42c765bacee7155f15a2951"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = "Fake cryptocurrency wallets builds leading to malicious RMM connections"

      signer              = "Perry Sabrina Ann"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:e8:b5:c8:b2:21:19:b0:b9:a9:60:00:00:00:07:e8:b5"
      cert_thumbprint     = "07DA992A36EAA3656C8C93DC5AA7EB9B7C2E880E"
      cert_valid_from     = "2026-04-06"
      cert_valid_to       = "2026-04-09"

      country             = "US"
      state               = "Hawaii"
      locality            = "Wailuku"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:e8:b5:c8:b2:21:19:b0:b9:a9:60:00:00:00:07:e8:b5"
      )
}
