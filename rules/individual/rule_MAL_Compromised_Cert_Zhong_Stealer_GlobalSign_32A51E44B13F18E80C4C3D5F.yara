import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_GlobalSign_32A51E44B13F18E80C4C3D5F {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-06-26"
      version             = "1.0"

      hash                = "862230807f82b8828b07f2f1c1ab1f7cc5a03a8efa428976d0b13415888ad3dc"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Taiyuan Yuansu E-commerce Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "32:a5:1e:44:b1:3f:18:e8:0c:4c:3d:5f"
      cert_thumbprint     = "DAEF347ACA15BA4F621AE75C767867397FF0F67F"
      cert_valid_from     = "2025-06-26"
      cert_valid_to       = "2026-06-27"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "91140105MAD80PPM5E"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "32:a5:1e:44:b1:3f:18:e8:0c:4c:3d:5f"
      )
}
