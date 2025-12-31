import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_008CA703D6A6A9FDFCD920C62316723EAC {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-12"
      version             = "1.0"

      hash                = "1d2f9b6680d3df883dceac3eb5dd35c13a9862ef0ba6f40603df5a1e54408c6e"
      malware             = "Zhong Stealer"
      malware_type        = "Infostealer"
      malware_notes       = "Malware is frequently disguised as a image or screenshot. Pulls second stages from legitimate CDN."

      signer              = "Luanchuan County Qiangsheng Information Engineering Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:8c:a7:03:d6:a6:a9:fd:fc:d9:20:c6:23:16:72:3e:ac"
      cert_thumbprint     = "4C489977809BB6A54E528532862CF1D9E4FA9990"
      cert_valid_from     = "2025-12-12"
      cert_valid_to       = "2026-12-12"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:8c:a7:03:d6:a6:a9:fd:fc:d9:20:c6:23:16:72:3e:ac"
      )
}
