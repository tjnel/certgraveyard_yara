import "pe"

rule MAL_Compromised_Cert_FakeImage_Certum_4C1D66965222EDE4519CB068D9C93B28 {
   meta:
      description         = "Detects FakeImage with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-08"
      version             = "1.0"

      hash                = "0ecf94aaad04c9bd55d2a41e809277e6c13f887b4d1edd94671aa76b986c646c"
      malware             = "FakeImage"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "武汉伽跃寻信息咨询有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4c:1d:66:96:52:22:ed:e4:51:9c:b0:68:d9:c9:3b:28"
      cert_thumbprint     = "4529F9496B4D9CF20028B9F3854B0EC624273A22"
      cert_valid_from     = "2026-06-08"
      cert_valid_to       = "2027-06-08"

      country             = "CN"
      state               = "湖北"
      locality            = "武汉"
      email               = "???"
      rdn_serial_number   = "91420104MAKDJ3FU8T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4c:1d:66:96:52:22:ed:e4:51:9c:b0:68:d9:c9:3b:28"
      )
}
