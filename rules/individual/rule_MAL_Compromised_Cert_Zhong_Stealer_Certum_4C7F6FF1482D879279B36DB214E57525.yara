import "pe"

rule MAL_Compromised_Cert_Zhong_Stealer_Certum_4C7F6FF1482D879279B36DB214E57525 {
   meta:
      description         = "Detects Zhong Stealer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-26"
      version             = "1.0"

      hash                = "e8afbf1004ae40d87fb25005117f692b97e889a4393cc790fbd7a5e8ffea46cb"
      malware             = "Zhong Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "广州栩冠科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4c:7f:6f:f1:48:2d:87:92:79:b3:6d:b2:14:e5:75:25"
      cert_thumbprint     = "56B676ED29FA650555B6E49043FAFA4B4BADE56F"
      cert_valid_from     = "2026-01-26"
      cert_valid_to       = "2027-01-26"

      country             = "CN"
      state               = "广东"
      locality            = "广州"
      email               = "???"
      rdn_serial_number   = "91440114MAD3CJDX3Q"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4c:7f:6f:f1:48:2d:87:92:79:b3:6d:b2:14:e5:75:25"
      )
}
