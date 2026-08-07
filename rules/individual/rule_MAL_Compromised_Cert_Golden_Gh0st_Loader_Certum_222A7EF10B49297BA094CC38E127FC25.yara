import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_222A7EF10B49297BA094CC38E127FC25 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-14"
      version             = "1.0"

      hash                = "2edb7c1f064cbfc7883f6a4be65134c8a27fba74413d9ed800b4e3ad192e8426"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Chengdu Yongyingli Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "22:2a:7e:f1:0b:49:29:7b:a0:94:cc:38:e1:27:fc:25"
      cert_thumbprint     = "d22c9f999bfb7315dd0d33f55594cdba49c3731a"
      cert_valid_from     = "2026-07-14"
      cert_valid_to       = "2027-07-14"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "22:2a:7e:f1:0b:49:29:7b:a0:94:cc:38:e1:27:fc:25"
      )
}
