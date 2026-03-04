import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_50699944C012F49C9F254B6900E78256 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "f3c11d0d18c5fe7c40c2ff833a618a46873ae99b0e7525f692d407395fd61b8b"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Astro Bright LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "50:69:99:44:c0:12:f4:9c:9f:25:4b:69:00:e7:82:56"
      cert_thumbprint     = "FE8AC01467F8E21806BA338E69DF21B5B7E74E78"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2026-05-21"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "50:69:99:44:c0:12:f4:9c:9f:25:4b:69:00:e7:82:56"
      )
}
