import "pe"

rule MAL_Compromised_Cert_AutoCAD_Trojan_Certum_21EC6FC7878BF7B28D994CF66DBFC994 {
   meta:
      description         = "Detects AutoCAD-Trojan with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-15"
      version             = "1.0"

      hash                = "17d2b3fb0c1942c43588d26ba9aecd6f6a9a549f86a8bb4120865cfbd9caf137"
      malware             = "AutoCAD-Trojan"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Guangzhou Recording Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "21:ec:6f:c7:87:8b:f7:b2:8d:99:4c:f6:6d:bf:c9:94"
      cert_thumbprint     = "5348cd6fd9db43cc8bff7285ca0194f3bb639a0efd3f49f764eaa35f262222f1"
      cert_valid_from     = "2025-04-15"
      cert_valid_to       = "2026-04-15"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "21:ec:6f:c7:87:8b:f7:b2:8d:99:4c:f6:6d:bf:c9:94"
      )
}
