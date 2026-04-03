import "pe"

rule MAL_Compromised_Cert_StatusLoader_Sectigo_00C0AC0D9E7DCACB044CFFBB68D24C7058 {
   meta:
      description         = "Detects StatusLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-13"
      version             = "1.0"

      hash                = "f062ad651c7e214b1bddc45fe9a927182ef2143a4007b7bbc48389e321855767"
      malware             = "StatusLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 62.164.177.107:9000/wmglb"

      signer              = "Xiamen Buling Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:c0:ac:0d:9e:7d:ca:cb:04:4c:ff:bb:68:d2:4c:70:58"
      cert_thumbprint     = "DC64DF1242DB011FBF1D0551EF0950411E729165"
      cert_valid_from     = "2026-01-13"
      cert_valid_to       = "2027-01-13"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350206MA34JFXG1D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:c0:ac:0d:9e:7d:ca:cb:04:4c:ff:bb:68:d2:4c:70:58"
      )
}
