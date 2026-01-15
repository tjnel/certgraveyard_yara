import "pe"

rule MAL_Compromised_Cert_TrojanizedTrading_Sectigo_5A6D707A84E6D581D2D31E9854A3AA15 {
   meta:
      description         = "Detects TrojanizedTrading with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-31"
      version             = "1.0"

      hash                = "51404e878db7b2140916b7e30606f1aeb9fd65738dd1e2ed18bc9487632212da"
      malware             = "TrojanizedTrading"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Gemini Technologies Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "5a:6d:70:7a:84:e6:d5:81:d2:d3:1e:98:54:a3:aa:15"
      cert_thumbprint     = "1B7A03C3ACA5EB546448614CCDFE7EA045459DE0"
      cert_valid_from     = "2025-10-31"
      cert_valid_to       = "2026-10-31"

      country             = "CN"
      state               = "Sichuan Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91510116MABQRT5848"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "5a:6d:70:7a:84:e6:d5:81:d2:d3:1e:98:54:a3:aa:15"
      )
}
