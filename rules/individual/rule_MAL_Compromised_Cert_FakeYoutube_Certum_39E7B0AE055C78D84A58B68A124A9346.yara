import "pe"

rule MAL_Compromised_Cert_FakeYoutube_Certum_39E7B0AE055C78D84A58B68A124A9346 {
   meta:
      description         = "Detects FakeYoutube with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-10"
      version             = "1.0"

      hash                = "08052e4a9ae060caa0d1ec7e4c671b113b8a4983ecd329fffb95e3b0179e399f"
      malware             = "FakeYoutube"
      malware_type        = "Unknown"
      malware_notes       = "A youtube client delivered from desktop-youtube[.]com"

      signer              = "TECHNOLOGY APPRAISALS LIMITED"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "39:e7:b0:ae:05:5c:78:d8:4a:58:b6:8a:12:4a:93:46"
      cert_thumbprint     = "46AD9991E541CC976547BE2532663136351944BA"
      cert_valid_from     = "2026-03-10"
      cert_valid_to       = "2027-03-10"

      country             = "GB"
      state               = "Greater London"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "01850356"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "39:e7:b0:ae:05:5c:78:d8:4a:58:b6:8a:12:4a:93:46"
      )
}
