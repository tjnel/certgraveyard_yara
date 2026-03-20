import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_611DC543A37DBAB0F4C982A437DD1C24 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-15"
      version             = "1.0"

      hash                = "356ca46f39b480d0ab523535f98e64ae0ec58fe1fdbb8ffc02f54b814445e9d0"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Enigmatic Saola LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "61:1d:c5:43:a3:7d:ba:b0:f4:c9:82:a4:37:dd:1c:24"
      cert_thumbprint     = "3FE2B96B13DA71E9E68D139621A6463514508F0C"
      cert_valid_from     = "2025-12-15"
      cert_valid_to       = "2026-12-15"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "61:1d:c5:43:a3:7d:ba:b0:f4:c9:82:a4:37:dd:1c:24"
      )
}
