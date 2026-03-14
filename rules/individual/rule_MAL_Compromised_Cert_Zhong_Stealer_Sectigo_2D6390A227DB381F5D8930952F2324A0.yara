import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_2D6390A227DB381F5D8930952F2324A0 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-21"
      version             = "1.0"

      hash                = "72c229baf23a09579a66f3121ced7038e1653158370ef0a4648cbc1a44c9d8a4"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xinsiyi (Ningbo) Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "2d:63:90:a2:27:db:38:1f:5d:89:30:95:2f:23:24:a0"
      cert_thumbprint     = "095354EE18F97620800877656C8685C73091EE91"
      cert_valid_from     = "2026-01-21"
      cert_valid_to       = "2027-01-21"

      country             = "CN"
      state               = "Zhejiang Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91330212MA2CK3JC8D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "2d:63:90:a2:27:db:38:1f:5d:89:30:95:2f:23:24:a0"
      )
}
