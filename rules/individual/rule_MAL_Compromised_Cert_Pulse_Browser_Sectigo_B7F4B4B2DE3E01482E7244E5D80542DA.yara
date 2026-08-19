import "pe"

rule MAL_Compromised_Cert_Pulse_Browser_Sectigo_B7F4B4B2DE3E01482E7244E5D80542DA {
   meta:
      description         = "Detects Pulse Browser with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-24"
      version             = "1.0"

      hash                = "85d11e03ed2c9b76334757ea80f61cd5703560cb4180b9e80e2e5ae3cf7e499e"
      malware             = "Pulse Browser"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alabama Technology USA, LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "b7:f4:b4:b2:de:3e:01:48:2e:72:44:e5:d8:05:42:da"
      cert_thumbprint     = "08a802ff1ef56fe63075a6d99cac10c5a3398c42"
      cert_valid_from     = "2025-09-24"
      cert_valid_to       = "2026-09-24"

      country             = "US"
      state               = "New Mexico"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "b7:f4:b4:b2:de:3e:01:48:2e:72:44:e5:d8:05:42:da"
      )
}
