import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00A4CC216FDD5C1571E0182589D6BE6B69 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-22"
      version             = "1.0"

      hash                = "00abba65982bc5a445e81692903d32a3e5c4f9c1d11ada50a6b3dcdf536ec085"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "VLD Riv & Sanering AB"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a4:cc:21:6f:dd:5c:15:71:e0:18:25:89:d6:be:6b:69"
      cert_thumbprint     = "6D0B11E746F6281307215B893032F56C1935D475"
      cert_valid_from     = "2024-01-22"
      cert_valid_to       = "2025-01-21"

      country             = "SE"
      state               = "Stockholms län"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "559265-2506"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a4:cc:21:6f:dd:5c:15:71:e0:18:25:89:d6:be:6b:69"
      )
}
