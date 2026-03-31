import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_00A8F8379EE21B6B3859DA939532512002 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "b38c9f871dc4735320464bb80219372a0ffe2b4f8750942b550576ace9b012b8"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Yufeng Tiantai Network Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a8:f8:37:9e:e2:1b:6b:38:59:da:93:95:32:51:20:02"
      cert_thumbprint     = "FBBE30902F0D6F10ABEFE71B8879CAC0339B0578"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2027-03-19"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350203MACUPRB30D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a8:f8:37:9e:e2:1b:6b:38:59:da:93:95:32:51:20:02"
      )
}
