import "pe"

rule MAL_Compromised_Cert_BlackMoon_Certum_3FC0EC5B90F9AA2F2C5F762F41C9E8C3 {
   meta:
      description         = "Detects BlackMoon with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-22"
      version             = "1.0"

      hash                = "8c8dcaf27395fc13e3f7ddb1d23b03715d8f23211619f3283e26ac992e346d8b"
      malware             = "BlackMoon"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sichuan Zhongqia Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "3f:c0:ec:5b:90:f9:aa:2f:2c:5f:76:2f:41:c9:e8:c3"
      cert_thumbprint     = "4cabc074583c6f03b8b58168a22113d875cb358f"
      cert_valid_from     = "2026-08-22"
      cert_valid_to       = "2027-08-22"

      country             = "CN"
      state               = "四川省"
      locality            = "绵阳市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "3f:c0:ec:5b:90:f9:aa:2f:2c:5f:76:2f:41:c9:e8:c3"
      )
}
