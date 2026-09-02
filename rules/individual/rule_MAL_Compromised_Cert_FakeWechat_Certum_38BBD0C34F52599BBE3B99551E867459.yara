import "pe"

rule MAL_Compromised_Cert_FakeWechat_Certum_38BBD0C34F52599BBE3B99551E867459 {
   meta:
      description         = "Detects FakeWechat with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-19"
      version             = "1.0"

      hash                = "1da8f4e1ce5896277bfee5b9f6628f29a7534ae830108387b6aabeb4204c7039"
      malware             = "FakeWechat"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Jiangxi Jinpin Environmental Protection Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "38:bb:d0:c3:4f:52:59:9b:be:3b:99:55:1e:86:74:59"
      cert_thumbprint     = "5d33dc09d27a2e5912868f7413e083c91b84b5b0"
      cert_valid_from     = "2026-08-19"
      cert_valid_to       = "2027-08-19"

      country             = "CN"
      state               = "Jiangxi"
      locality            = "Ganzhou"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "38:bb:d0:c3:4f:52:59:9b:be:3b:99:55:1e:86:74:59"
      )
}
