import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_00C30AE522FF59DD703FF3F27A2A9BCCCD {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-30"
      version             = "1.0"

      hash                = "3f049dd0ef4d209cce7ac081c093d51bcf2c5c3e515d8c124c63b31c8310e1d2"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Yaolun Network Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:c3:0a:e5:22:ff:59:dd:70:3f:f3:f2:7a:2a:9b:cc:cd"
      cert_thumbprint     = "9A85F613AE304BF80A85ADBEF5C30D72FB484840"
      cert_valid_from     = "2026-03-30"
      cert_valid_to       = "2027-03-30"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350205MA3218P27M"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:c3:0a:e5:22:ff:59:dd:70:3f:f3:f2:7a:2a:9b:cc:cd"
      )
}
