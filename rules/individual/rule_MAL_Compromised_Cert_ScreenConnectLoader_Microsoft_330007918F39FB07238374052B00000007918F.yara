import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330007918F39FB07238374052B00000007918F {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "909b9ee17a71d51d04bb1acd9fc6e8286f9adb316b763f5d9d2c654453ad6637"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JORGE LOPEZ"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:91:8f:39:fb:07:23:83:74:05:2b:00:00:00:07:91:8f"
      cert_thumbprint     = "928B37D471D65A2A1B6CD2709A7C9FBF263335BF"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2026-03-26"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:91:8f:39:fb:07:23:83:74:05:2b:00:00:00:07:91:8f"
      )
}
