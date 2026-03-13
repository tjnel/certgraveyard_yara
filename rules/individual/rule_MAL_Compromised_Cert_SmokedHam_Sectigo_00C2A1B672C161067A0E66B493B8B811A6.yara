import "pe"

rule MAL_Compromised_Cert_SmokedHam_Sectigo_00C2A1B672C161067A0E66B493B8B811A6 {
   meta:
      description         = "Detects SmokedHam with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-13"
      version             = "1.0"

      hash                = "43dccf680d3f059389aab714cf9e6b04b8249ae173be671c2425c6df3335e0fd"
      malware             = "SmokedHam"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Shuangbaishi Information Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:c2:a1:b6:72:c1:61:06:7a:0e:66:b4:93:b8:b8:11:a6"
      cert_thumbprint     = "2C197EA3FB939A310D2F63A9BA683E1CAF00FB52"
      cert_valid_from     = "2026-01-13"
      cert_valid_to       = "2027-01-13"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:c2:a1:b6:72:c1:61:06:7a:0e:66:b4:93:b8:b8:11:a6"
      )
}
