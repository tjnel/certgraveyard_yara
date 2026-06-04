import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Certum_5BD368336404058DA643D99A3BBEB530 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-18"
      version             = "1.0"

      hash                = "a60f58618c8548ff60978d7c50176bebb38486690d87ba24a8581b62dd478228"
      malware             = "Zhong Stealer"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Biao Zhao"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "5b:d3:68:33:64:04:05:8d:a6:43:d9:9a:3b:be:b5:30"
      cert_thumbprint     = "90E412614B391AB2F0CAF9C2D91761B79BAE1505"
      cert_valid_from     = "2026-03-18"
      cert_valid_to       = "2027-03-18"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Nanchong"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "5b:d3:68:33:64:04:05:8d:a6:43:d9:9a:3b:be:b5:30"
      )
}
