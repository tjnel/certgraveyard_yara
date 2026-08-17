import "pe"

rule MAL_Compromised_Cert_FakeAITrading_Certum_1B289187F974E8F854F1CE87C1200AF3 {
   meta:
      description         = "Detects FakeAITrading with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-19"
      version             = "1.0"

      hash                = "97019c044e5448c083ea0b4c77797d228d1e982f29d604a6d261a2c0d86e41df"
      malware             = "FakeAITrading"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ziyan Zeng"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "1b:28:91:87:f9:74:e8:f8:54:f1:ce:87:c1:20:0a:f3"
      cert_thumbprint     = "832b6d8ed7d4dc3042bcc8ca91f73bf4a2843f57"
      cert_valid_from     = "2026-01-19"
      cert_valid_to       = "2027-01-19"

      country             = "CN"
      state               = "Jiangxi"
      locality            = "Zhangshu"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "1b:28:91:87:f9:74:e8:f8:54:f1:ce:87:c1:20:0a:f3"
      )
}
