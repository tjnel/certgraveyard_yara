import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_38BF78674DA7DED94863D622BA150FDB {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "7c995c884d4e3b0d38157c510bcc37cd7a8ca35ae24eb1ea0c7e52d76b8a7dca"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "Xiamen Dahonghuo Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "38:bf:78:67:4d:a7:de:d9:48:63:d6:22:ba:15:0f:db"
      cert_thumbprint     = "6330EC795E2B93B4A2221A78C25CFCD578A04A02"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2027-03-19"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350206MA34UAC54C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "38:bf:78:67:4d:a7:de:d9:48:63:d6:22:ba:15:0f:db"
      )
}
