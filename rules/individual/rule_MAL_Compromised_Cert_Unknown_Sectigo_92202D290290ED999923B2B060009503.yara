import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_92202D290290ED999923B2B060009503 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-13"
      version             = "1.0"

      hash                = "3759759137cf730b7046c49c3c85bafa8cf6102b81d3920fdc1930d9735706e6"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Lway Firmware"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "92:20:2d:29:02:90:ed:99:99:23:b2:b0:60:00:95:03"
      cert_thumbprint     = "76f6ffcc3f27898297f2b2f506c14b128cb1429c"
      cert_valid_from     = "2026-09-13"
      cert_valid_to       = "2027-09-13"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "92:20:2d:29:02:90:ed:99:99:23:b2:b0:60:00:95:03"
      )
}
