import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Sectigo_3EAA4BD40D5DA98036B33023E0052869 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-26"
      version             = "1.0"

      hash                = "b1e6036407ac561deebf5a4885fda4d63686bdfbf808524e7554ea339a7bbe39"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Shunhuitong E-commerce Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "3e:aa:4b:d4:0d:5d:a9:80:36:b3:30:23:e0:05:28:69"
      cert_thumbprint     = "E579AB4491E4C3B9FCA255D36A7B269E14DB36A2"
      cert_valid_from     = "2026-03-26"
      cert_valid_to       = "2027-03-26"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350203MA2YCK984W"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "3e:aa:4b:d4:0d:5d:a9:80:36:b3:30:23:e0:05:28:69"
      )
}
