import "pe"

rule MAL_Compromised_Cert_Unknown_Apple_407FA5247F0B37B7 {
   meta:
      description         = "Detects Unknown with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-29"
      version             = "1.0"

      hash                = "3a9d703ba7f7564399365db7ab8b04238806ef7a53df0b6822f32b80bf0f5a80"
      malware             = "Unknown"
      malware_type        = "Backdoor"
      malware_notes       = ""

      signer              = "Emil Grigorov"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "40:7f:a5:24:7f:0b:37:b7"
      cert_thumbprint     = "9A3CE73387AD7069A0919EF6E09B5D3FCC9B2B31"
      cert_valid_from     = "2026-06-29"
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
         sig.serial == "40:7f:a5:24:7f:0b:37:b7"
      )
}
