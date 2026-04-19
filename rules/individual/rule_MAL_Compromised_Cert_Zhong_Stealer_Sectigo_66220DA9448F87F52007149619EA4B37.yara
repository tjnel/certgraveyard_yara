import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_66220DA9448F87F52007149619EA4B37 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "4d8c02745ed4c2bcd9bdb425d5763ebd1e6da459c1877fe9d0005e477622aa6a"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = ""

      signer              = "Xiamen Xianghe Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "66:22:0d:a9:44:8f:87:f5:20:07:14:96:19:ea:4b:37"
      cert_thumbprint     = "67BCBFBD0D412E47C0E70F85778F69C6BFBBD7AF"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-04-01"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350205MAE1741T6H"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "66:22:0d:a9:44:8f:87:f5:20:07:14:96:19:ea:4b:37"
      )
}
