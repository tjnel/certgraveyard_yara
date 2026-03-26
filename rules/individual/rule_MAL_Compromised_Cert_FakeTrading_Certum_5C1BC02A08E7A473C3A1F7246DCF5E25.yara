import "pe"

rule MAL_Compromised_Cert_FakeTrading_Certum_5C1BC02A08E7A473C3A1F7246DCF5E25 {
   meta:
      description         = "Detects FakeTrading with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-13"
      version             = "1.0"

      hash                = "c5baf8fe00350ce8d1117384ad520583e7742797f3b57d7dcc1a9d759172d2b7"
      malware             = "FakeTrading"
      malware_type        = "Unknown"
      malware_notes       = "Fake crypto trading applications via SEO poisoning"

      signer              = "Amerra Finland Oy"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5c:1b:c0:2a:08:e7:a4:73:c3:a1:f7:24:6d:cf:5e:25"
      cert_thumbprint     = "F19E6FF15F522806C0C15167EBF7DAB4DE86073F"
      cert_valid_from     = "2026-03-13"
      cert_valid_to       = "2027-03-13"

      country             = "FI"
      state               = "North Savo"
      locality            = "Kuopio"
      email               = "???"
      rdn_serial_number   = "1860677-2"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5c:1b:c0:2a:08:e7:a4:73:c3:a1:f7:24:6d:cf:5e:25"
      )
}
