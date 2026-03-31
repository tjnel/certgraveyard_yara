import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_3D750F9AC0E074D810BCF82573950AF3 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "e913b436fe3debd25ed0fa24e84e313f104490be66687a584f9cc15e0b23d9c8"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Longhu Sanlu E-commerce Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "3d:75:0f:9a:c0:e0:74:d8:10:bc:f8:25:73:95:0a:f3"
      cert_thumbprint     = "4023C8F4A6A4FC50A59D64B697482A79EEE367EC"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2027-03-19"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350203094066632J"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "3d:75:0f:9a:c0:e0:74:d8:10:bc:f8:25:73:95:0a:f3"
      )
}
