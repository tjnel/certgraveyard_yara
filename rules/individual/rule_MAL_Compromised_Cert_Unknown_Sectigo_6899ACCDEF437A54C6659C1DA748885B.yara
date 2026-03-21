import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_6899ACCDEF437A54C6659C1DA748885B {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-28"
      version             = "1.0"

      hash                = "636a19027310285bcdfbf4aac1a419d7c1851ed68b68c663d88403ebf8188946"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sirius One LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "68:99:ac:cd:ef:43:7a:54:c6:65:9c:1d:a7:48:88:5b"
      cert_thumbprint     = "05D81693FBDB9D45D4A16AC5B1B3577565C9B63C"
      cert_valid_from     = "2025-10-28"
      cert_valid_to       = "2026-10-28"

      country             = "IL"
      state               = "Tel Aviv"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "517124012"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "68:99:ac:cd:ef:43:7a:54:c6:65:9c:1d:a7:48:88:5b"
      )
}
