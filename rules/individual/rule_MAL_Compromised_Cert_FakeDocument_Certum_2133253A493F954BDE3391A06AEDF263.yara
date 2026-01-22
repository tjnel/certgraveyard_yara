import "pe"

rule MAL_Compromised_Cert_FakeDocument_Certum_2133253A493F954BDE3391A06AEDF263 {
   meta:
      description         = "Detects FakeDocument with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-17"
      version             = "1.0"

      hash                = "2027ed1e4a19434b02f23bfd72221eb54408f1f56ee1a44c75fe1aca861a2f41"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installer disguised as a fake invoice delivering unkown stealer via HijackLoader. Ref: https://app.any.run/tasks/da709fd9-f8fd-46d6-a939-55369bbb1fbc"

      signer              = "天津语奥科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "21:33:25:3a:49:3f:95:4b:de:33:91:a0:6a:ed:f2:63"
      cert_thumbprint     = "8386DB3C54A8D75F6EF76BE8DC95348435A44ED5"
      cert_valid_from     = "2025-04-17"
      cert_valid_to       = "2026-04-17"

      country             = "CN"
      state               = "天津"
      locality            = "天津"
      email               = "???"
      rdn_serial_number   = "91120102MAD7KFG849"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "21:33:25:3a:49:3f:95:4b:de:33:91:a0:6a:ed:f2:63"
      )
}
