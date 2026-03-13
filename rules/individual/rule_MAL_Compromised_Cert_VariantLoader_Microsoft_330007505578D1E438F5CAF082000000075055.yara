import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_330007505578D1E438F5CAF082000000075055 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-08"
      version             = "1.0"

      hash                = "08bc9fb05cc6a402804721d9c28c6814d2e78159efdc41f0e0180af7a3bbfd86"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 188.137.246.189"

      signer              = "DIGITAL ADVERTISING BUSINESS INFLUENCERS S.R.L."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:50:55:78:d1:e4:38:f5:ca:f0:82:00:00:00:07:50:55"
      cert_thumbprint     = "78287A90FCB3E737A40B60392EBDD332607863FB"
      cert_valid_from     = "2026-03-08"
      cert_valid_to       = "2026-03-11"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:50:55:78:d1:e4:38:f5:ca:f0:82:00:00:00:07:50:55"
      )
}
