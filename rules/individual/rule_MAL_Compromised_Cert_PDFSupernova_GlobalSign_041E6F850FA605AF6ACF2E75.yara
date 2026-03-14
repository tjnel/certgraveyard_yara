import "pe"

rule MAL_Compromised_Cert_PDFSupernova_GlobalSign_041E6F850FA605AF6ACF2E75 {
   meta:
      description         = "Detects PDFSupernova with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-27"
      version             = "1.0"

      hash                = "b4c08722442b890a0219b005c47e7ebd0b45e9b54ff196d8c5e4f50b0f38fa80"
      malware             = "PDFSupernova"
      malware_type        = "Browser Hijacker"
      malware_notes       = "This fake PDF editor hijacks the user's browser, see more documentation here: https://blog.lukeacha.com/2025/11/fake-pdf-converter-hides-dark-secret.html"

      signer              = "Magnivicent LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "04:1e:6f:85:0f:a6:05:af:6a:cf:2e:75"
      cert_thumbprint     = "848E462A49B1ECFB455A828F40194429DA31EAF1"
      cert_valid_from     = "2026-01-27"
      cert_valid_to       = "2027-01-28"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "Holon"
      email               = "???"
      rdn_serial_number   = "517165643"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "04:1e:6f:85:0f:a6:05:af:6a:cf:2e:75"
      )
}
