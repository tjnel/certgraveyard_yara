import "pe"

rule MAL_Compromised_Cert_FakeAdvancedIPScanner_GlobalSign_756644768CDFC34FD79A60CD {
   meta:
      description         = "Detects FakeAdvancedIPScanner with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-06"
      version             = "1.0"

      hash                = "7e3ebe3a7431860023fdaf0944347f76db0879c98cb4f80659a8b7172a2c8965"
      malware             = "FakeAdvancedIPScanner"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Code Beyond d.o.o."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "75:66:44:76:8c:df:c3:4f:d7:9a:60:cd"
      cert_thumbprint     = "e84366084ada4746bde5ff3c9a086737ecd2d7bc"
      cert_valid_from     = "2026-08-06"
      cert_valid_to       = "2027-08-07"

      country             = "HR"
      state               = "Grad Zagreb"
      locality            = "Zagreb"
      email               = "filip@codebeyond.io"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "75:66:44:76:8c:df:c3:4f:d7:9a:60:cd"
      )
}
