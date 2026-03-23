import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_00EF0E84C496252CF958D7D34547D1CD38 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-10"
      version             = "1.0"

      hash                = "854199a6ac5501a4911921d8d24b4475aac440228b00db3c90a126484dfb03af"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Botania Games LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ef:0e:84:c4:96:25:2c:f9:58:d7:d3:45:47:d1:cd:38"
      cert_thumbprint     = "EDDD606288D89DDCA78C13CFF3C395491A6B74F7"
      cert_valid_from     = "2026-03-10"
      cert_valid_to       = "2027-03-10"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ef:0e:84:c4:96:25:2c:f9:58:d7:d3:45:47:d1:cd:38"
      )
}
