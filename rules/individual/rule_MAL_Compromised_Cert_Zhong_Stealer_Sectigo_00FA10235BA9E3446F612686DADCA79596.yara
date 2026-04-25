import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_00FA10235BA9E3446F612686DADCA79596 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "7860dd085d9db6ff2fb594d9bbca23095779dc2bc7d9a201f76d5e0a285549ef"
      malware             = "Zhong Stealer"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Xiamen Senxing Shengxuan Network Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:fa:10:23:5b:a9:e3:44:6f:61:26:86:da:dc:a7:95:96"
      cert_thumbprint     = "D626074CB387F1DEA516E5F2CE99842C85E0A983"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-04-01"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350205MAE56T5274"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:fa:10:23:5b:a9:e3:44:6f:61:26:86:da:dc:a7:95:96"
      )
}
