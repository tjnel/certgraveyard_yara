import "pe"

rule MAL_Compromised_Cert_FakeDocument_Certum_7836FC681AAE72E82815B7A3654DBF01 {
   meta:
      description         = "Detects FakeDocument with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-25"
      version             = "1.0"

      hash                = "6161c1e746b8e29297917c72f93652a137691a3b9d4c6d6fbce38f80f7732d34"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xidao E-commerce Studio, Yishui County"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "78:36:fc:68:1a:ae:72:e8:28:15:b7:a3:65:4d:bf:01"
      cert_thumbprint     = "ec371bcba3e1d42f1126bd8562d7b07022b9d9eb"
      cert_valid_from     = "2026-08-25"
      cert_valid_to       = "2027-08-25"

      country             = "CN"
      state               = "山东省"
      locality            = "临沂市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "78:36:fc:68:1a:ae:72:e8:28:15:b7:a3:65:4d:bf:01"
      )
}
