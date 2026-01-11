import "pe"

rule MAL_Compromised_Cert_Odyssey_Stealer_Apple_5DDABE521195AE49 {
   meta:
      description         = "Detects Odyssey Stealer with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-09"
      version             = "1.0"

      hash                = "fbc3d4819f01f2d9d31ecb420d3a9efa12cc4e6bf98415edfffbe99656cdff44"
      malware             = "Odyssey Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sandrine Lecours"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "5d:da:be:52:11:95:ae:49"
      cert_thumbprint     = "A48CE0006A8C4B0761CF2BA639E3C80B7DFC5146"
      cert_valid_from     = "2026-01-09"
      cert_valid_to       = "2027-02-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "5d:da:be:52:11:95:ae:49"
      )
}
