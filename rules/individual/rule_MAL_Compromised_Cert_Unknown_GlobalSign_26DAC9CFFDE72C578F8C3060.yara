import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_26DAC9CFFDE72C578F8C3060 {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-03"
      version             = "1.0"

      hash                = "c8a2bde264c1898a38ef5fb2a5bff198c5c2908ec7a4ea66b59681ab9bf82f46"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "M & V SOLUTIONS CO., LTD."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "26:da:c9:cf:fd:e7:2c:57:8f:8c:30:60"
      cert_thumbprint     = "191f4e0a8fad139601d81d57e2315b0ca31864dcc352f7ce478819d1a3b32889"
      cert_valid_from     = "2025-11-03"
      cert_valid_to       = "2026-11-04"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "26:da:c9:cf:fd:e7:2c:57:8f:8c:30:60"
      )
}
