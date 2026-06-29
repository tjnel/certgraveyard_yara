import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000EACC8C1FE72D2498E15600000000EACC {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-09"
      version             = "1.0"

      hash                = "7b0cc3a8616cb050be7dee985f0306d3677603eac196958678ec6af8951bfdce"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Avery Benavidez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:ea:cc:8c:1f:e7:2d:24:98:e1:56:00:00:00:00:ea:cc"
      cert_thumbprint     = "52CE8C9D2EC115FD7255D76E5587205CC7728BA7"
      cert_valid_from     = "2026-05-09"
      cert_valid_to       = "2026-05-12"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:ea:cc:8c:1f:e7:2d:24:98:e1:56:00:00:00:00:ea:cc"
      )
}
