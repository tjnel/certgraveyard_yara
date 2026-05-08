import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000CBA85784F7176318EEAA00000000CBA8 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-05"
      version             = "1.0"

      hash                = "dbd71bb5a28bdef71119d467d685a00a88d84ff925f43b87330a0152259fb784"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CHRISTIAN TORRES"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:cb:a8:57:84:f7:17:63:18:ee:aa:00:00:00:00:cb:a8"
      cert_thumbprint     = "1AD393169FAE0D4A2B6BF5A027E75246FFC60DED"
      cert_valid_from     = "2026-05-05"
      cert_valid_to       = "2026-05-08"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:cb:a8:57:84:f7:17:63:18:ee:aa:00:00:00:00:cb:a8"
      )
}
