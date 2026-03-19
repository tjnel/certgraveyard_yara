import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Sectigo_5254E162E2F5628B0D8540EE17F56995 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-04"
      version             = "1.0"

      hash                = "d4f085a345cd8a3f662711ea7f8f72084bb7367085912028b7f4acc4e30f3d9e"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Lway Firmware"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "52:54:e1:62:e2:f5:62:8b:0d:85:40:ee:17:f5:69:95"
      cert_thumbprint     = "352DA60D57818350C65D40130ED087A2F58FD596"
      cert_valid_from     = "2026-03-04"
      cert_valid_to       = "2027-06-02"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "3462375-9"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "52:54:e1:62:e2:f5:62:8b:0d:85:40:ee:17:f5:69:95"
      )
}
