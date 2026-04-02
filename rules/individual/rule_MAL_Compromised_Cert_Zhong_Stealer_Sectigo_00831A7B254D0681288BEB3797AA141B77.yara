import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_00831A7B254D0681288BEB3797AA141B77 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "04f4dde250db15de247e67ecd25134ab7e4512a77859589f4e979905685316c0"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Liuyong Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:83:1a:7b:25:4d:06:81:28:8b:eb:37:97:aa:14:1b:77"
      cert_thumbprint     = "B7C2421E3A96AD5615E13844710A7BE0E74802D5"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2027-03-19"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350206MACPMBLY32"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:83:1a:7b:25:4d:06:81:28:8b:eb:37:97:aa:14:1b:77"
      )
}
