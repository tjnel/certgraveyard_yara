import "pe"

rule MAL_Compromised_Cert_PackClient_Certum_581F78AE1E23067BAFF8F1A57A73B718 {
   meta:
      description         = "Detects PackClient with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-04"
      version             = "1.0"

      hash                = "dc27bb3c16f98f11a2cdb88be7c4d3edf8348ce5b1a9334f5bd2e569f3cbf050"
      malware             = "PackClient"
      malware_type        = "Remote access tool"
      malware_notes       = "https://rogueauthority.org/signed-silentsetup-packclient-rat-driver"

      signer              = "Zaozhuang ZhongStore District HaoYouhao Department"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "58:1f:78:ae:1e:23:06:7b:af:f8:f1:a5:7a:73:b7:18"
      cert_thumbprint     = "006511f1b0761653407c6720c9f95c4a9c2a7e5a"
      cert_valid_from     = "2026-09-04"
      cert_valid_to       = "2027-09-04"

      country             = "CN"
      state               = "山东省"
      locality            = "枣庄市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "58:1f:78:ae:1e:23:06:7b:af:f8:f1:a5:7a:73:b7:18"
      )
}
