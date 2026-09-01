import "pe"

rule MAL_Compromised_Cert_FakeRVTools_Certum_5768DFBE1503EE4F524283EAB21065B8 {
   meta:
      description         = "Detects FakeRVTools with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-14"
      version             = "1.0"

      hash                = "83e297cd50a7076d445707cb91812d432a039a2721aae31088dd3913bcdbd781"
      malware             = "FakeRVTools"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SAN SOFTWARE, TOO"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "57:68:df:be:15:03:ee:4f:52:42:83:ea:b2:10:65:b8"
      cert_thumbprint     = "ce437f63c51a434b604c63d412f0b046ba3b3f35"
      cert_valid_from     = "2026-04-14"
      cert_valid_to       = "2027-04-14"

      country             = "KZ"
      state               = "Aktobe Region"
      locality            = "Aktobe"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "57:68:df:be:15:03:ee:4f:52:42:83:ea:b2:10:65:b8"
      )
}
