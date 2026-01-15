import "pe"

rule MAL_Compromised_Cert_PureHVNC_Certum_65F02736623718993AC28B6B704ED42F {
   meta:
      description         = "Detects PureHVNC with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-31"
      version             = "1.0"

      hash                = "cd5a928b4dd019414baf2eb61f6346eb3601bb3b7a8efaf960d1c56ae5de60db"
      malware             = "PureHVNC"
      malware_type        = "Unknown"
      malware_notes       = "Fake bill statement - https://app.any.run/tasks/cf40c46e-ca4c-40c6-bbbf-35bb0c613798"

      signer              = "Yijian Dingfang (Guangzhou) Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "65:f0:27:36:62:37:18:99:3a:c2:8b:6b:70:4e:d4:2f"
      cert_thumbprint     = "BBC857DD45BACC1C4420B8A2A88DF2FFF91AA209"
      cert_valid_from     = "2025-12-31"
      cert_valid_to       = "2026-12-31"

      country             = "CN"
      state               = "Guangdong"
      locality            = "Guangzhou"
      email               = "???"
      rdn_serial_number   = "91440101MA5CR70Q63"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "65:f0:27:36:62:37:18:99:3a:c2:8b:6b:70:4e:d4:2f"
      )
}
