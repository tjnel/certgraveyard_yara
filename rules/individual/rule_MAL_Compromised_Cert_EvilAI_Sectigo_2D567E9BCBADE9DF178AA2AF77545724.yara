import "pe"

rule MAL_Compromised_Cert_EvilAI_Sectigo_2D567E9BCBADE9DF178AA2AF77545724 {
   meta:
      description         = "Detects EvilAI with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-29"
      version             = "1.0"

      hash                = "ae91e1e3316e47747182650317f0a1810426bfc9a70d1dc46d4d12b3e2f79fa0"
      malware             = "EvilAI"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chengdu Jiadao Hexin Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "2d:56:7e:9b:cb:ad:e9:df:17:8a:a2:af:77:54:57:24"
      cert_thumbprint     = "FC638FFC7932F858EDB8E97E54EDCE1BB0CAD264"
      cert_valid_from     = "2025-11-29"
      cert_valid_to       = "2026-11-29"

      country             = "CN"
      state               = "Sichuan Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91510124MAACHUX355"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "2d:56:7e:9b:cb:ad:e9:df:17:8a:a2:af:77:54:57:24"
      )
}
