import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_00EFCDE65B00EF4F8F30A7D043BAE2AE88 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-19"
      version             = "1.0"

      hash                = "551006be1d93d5c26f5eb7596b471756350d31fad728c708d52a88b6bc3f82f3"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Wuan Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ef:cd:e6:5b:00:ef:4f:8f:30:a7:d0:43:ba:e2:ae:88"
      cert_thumbprint     = "0261E2909D75EA34D54D97993136243A8D7081EA"
      cert_valid_from     = "2026-01-19"
      cert_valid_to       = "2027-01-19"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ef:cd:e6:5b:00:ef:4f:8f:30:a7:d0:43:ba:e2:ae:88"
      )
}
