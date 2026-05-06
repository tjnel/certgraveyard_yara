import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_330000B194F757CFE96A2702FC00000000B194 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-02"
      version             = "1.0"

      hash                = "4fdd6d68b2278861eda0c75c7590e08996671b580970e5ee76dcd1fa476aeb1c"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SERPENTINE SOLAR LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:b1:94:f7:57:cf:e9:6a:27:02:fc:00:00:00:00:b1:94"
      cert_thumbprint     = "1F1997A13BA667FC5467DACBFDDCF3CE803A4192"
      cert_valid_from     = "2026-05-02"
      cert_valid_to       = "2026-05-05"

      country             = "IE"
      state               = "Dublin"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:b1:94:f7:57:cf:e9:6a:27:02:fc:00:00:00:00:b1:94"
      )
}
