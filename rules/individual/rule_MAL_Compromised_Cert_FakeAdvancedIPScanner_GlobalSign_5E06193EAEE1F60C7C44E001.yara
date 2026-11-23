import "pe"

rule MAL_Compromised_Cert_FakeAdvancedIPScanner_GlobalSign_5E06193EAEE1F60C7C44E001 {
   meta:
      description         = "Detects FakeAdvancedIPScanner with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-30"
      version             = "1.0"

      hash                = "290d243388e5d690d6142344239602ff7983fb1b8758e1c1f1720f076f482806"
      malware             = "FakeAdvancedIPScanner"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Listenmaa Consulting Oy"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5e:06:19:3e:ae:e1:f6:0c:7c:44:e0:01"
      cert_thumbprint     = "87e7d5cf28ee404dee2a447cf50ff49cdc0c8797"
      cert_valid_from     = "2026-09-30"
      cert_valid_to       = "2027-10-01"

      country             = "FI"
      state               = "Pirkanmaa"
      locality            = "Tampere"
      email               = "jani@listenmaa.com"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5e:06:19:3e:ae:e1:f6:0c:7c:44:e0:01"
      )
}
