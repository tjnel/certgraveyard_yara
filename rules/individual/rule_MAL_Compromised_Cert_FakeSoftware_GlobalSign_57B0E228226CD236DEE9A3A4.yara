import "pe"

rule MAL_Compromised_Cert_FakeSoftware_GlobalSign_57B0E228226CD236DEE9A3A4 {
   meta:
      description         = "Detects FakeSoftware with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-30"
      version             = "1.0"

      hash                = "51bc148112dd41973b750315d51fa8365c3d293a32b945a5f927aba9f03b47b6"
      malware             = "FakeSoftware"
      malware_type        = "Unknown"
      malware_notes       = "C2:  167.253.157.132"

      signer              = "CODE LOFTS d.o.o."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "57:b0:e2:28:22:6c:d2:36:de:e9:a3:a4"
      cert_thumbprint     = "a21220ccdcf4a6c2a38ef235f26b75a7a05f4624"
      cert_valid_from     = "2026-07-30"
      cert_valid_to       = "2027-07-31"

      country             = "HR"
      state               = "Split-Dalmatia"
      locality            = "Split"
      email               = "info@codelofts.com"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "57:b0:e2:28:22:6c:d2:36:de:e9:a3:a4"
      )
}
