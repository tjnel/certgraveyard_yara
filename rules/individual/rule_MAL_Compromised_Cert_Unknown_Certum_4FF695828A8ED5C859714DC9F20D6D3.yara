import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_4FF695828A8ED5C859714DC9F20D6D3 {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-03"
      version             = "1.0"

      hash                = "c459fdd1f0a39b4de680a45f20a822b204ca897437b4aff99f088f0067a11327"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "Fake cursor install."

      signer              = "杭州思维宇宙科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4f:f6:95:82:8a:8e:d5:c8:59:71:4d:c9:f2:0d:6d:3"
      cert_thumbprint     = "31e7b45373da3201b5dbf16c1047d0fa0302143d"
      cert_valid_from     = "2026-03-03"
      cert_valid_to       = "2027-03-03"

      country             = "CN"
      state               = "浙江"
      locality            = "杭州"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4f:f6:95:82:8a:8e:d5:c8:59:71:4d:c9:f2:0d:6d:3"
      )
}
