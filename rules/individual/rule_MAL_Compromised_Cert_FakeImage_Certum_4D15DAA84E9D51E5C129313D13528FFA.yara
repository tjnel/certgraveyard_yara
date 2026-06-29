import "pe"

rule MAL_Compromised_Cert_FakeImage_Certum_4D15DAA84E9D51E5C129313D13528FFA {
   meta:
      description         = "Detects FakeImage with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-28"
      version             = "1.0"

      hash                = "ac2ee3bda0a9616d27341b36e0bae58c61515cf99208ec3251f93ae30f955889"
      malware             = "FakeImage"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "中山合艾与诚电子有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4d:15:da:a8:4e:9d:51:e5:c1:29:31:3d:13:52:8f:fa"
      cert_thumbprint     = "2B466BC5856D7ECF1619F6ED8408152C889C14CD"
      cert_valid_from     = "2026-05-28"
      cert_valid_to       = "2027-05-28"

      country             = "CN"
      state               = "广东"
      locality            = "中山"
      email               = "???"
      rdn_serial_number   = "91442000MAE6TR835Y"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4d:15:da:a8:4e:9d:51:e5:c1:29:31:3d:13:52:8f:fa"
      )
}
