import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_660397BCD702EFA1C80BD5BC {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-17"
      version             = "1.0"

      hash                = "ffde5fbba662c27dbdf89236b16c80fcef3e5552d8ff98c052dd69b434fadf15"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Virtual Holding Resources, LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "66:03:97:bc:d7:02:ef:a1:c8:0b:d5:bc"
      cert_thumbprint     = "3fc914b6bc6c682fa9cbb37fe8ab5c5d5672de87"
      cert_valid_from     = "2026-03-17"
      cert_valid_to       = "2027-03-18"

      country             = "US"
      state               = "Texas"
      locality            = "The Woodlands"
      email               = "cdunlop@vhrtools.com"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "66:03:97:bc:d7:02:ef:a1:c8:0b:d5:bc"
      )
}
