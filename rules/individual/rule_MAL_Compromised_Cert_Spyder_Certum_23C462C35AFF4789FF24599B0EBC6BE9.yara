import "pe"

rule MAL_Compromised_Cert_Spyder_Certum_23C462C35AFF4789FF24599B0EBC6BE9 {
   meta:
      description         = "Detects Spyder with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-28"
      version             = "1.0"

      hash                = "1753abbd3a79ff9db264b3e05bbbd2fa6f0b983de1a66c341a8a4cc71b4d6429"
      malware             = "Spyder"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Shandong Hongfu Information Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "23:c4:62:c3:5a:ff:47:89:ff:24:59:9b:0e:bc:6b:e9"
      cert_thumbprint     = "b915200e731d43f900d57af7a2de8467638282ca"
      cert_valid_from     = "2024-06-28"
      cert_valid_to       = "2025-06-28"

      country             = "CN"
      state               = "Shandong"
      locality            = "Linyi"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "23:c4:62:c3:5a:ff:47:89:ff:24:59:9b:0e:bc:6b:e9"
      )
}
