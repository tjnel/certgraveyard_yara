import "pe"

rule MAL_Compromised_Cert_EvilAI_Sectigo_00CC30AD05F738E13861377BC08D188AE3 {
   meta:
      description         = "Detects EvilAI with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-20"
      version             = "1.0"

      hash                = "a1df99ad45cb2c14c2d9f582f41877715ee59bef6f7af761ae8972580e730ee1"
      malware             = "EvilAI"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Juyoupin Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:cc:30:ad:05:f7:38:e1:38:61:37:7b:c0:8d:18:8a:e3"
      cert_thumbprint     = "63D108A5673C28BC0E3D3533AB35265C5C4C667D"
      cert_valid_from     = "2026-01-20"
      cert_valid_to       = "2027-01-20"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350200MA8T7LY50L"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:cc:30:ad:05:f7:38:e1:38:61:37:7b:c0:8d:18:8a:e3"
      )
}
