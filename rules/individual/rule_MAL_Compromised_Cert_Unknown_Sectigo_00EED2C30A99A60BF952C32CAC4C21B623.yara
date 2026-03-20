import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00EED2C30A99A60BF952C32CAC4C21B623 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-11"
      version             = "1.0"

      hash                = "a880d9a03e9c9689802831e3e038d938b3379f5cfb5475ecbac6f681e14664c8"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Brand Flux Marketing LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ee:d2:c3:0a:99:a6:0b:f9:52:c3:2c:ac:4c:21:b6:23"
      cert_thumbprint     = "4DBDBA51B67B8A5D65806909F0000504E5CAA720"
      cert_valid_from     = "2025-11-11"
      cert_valid_to       = "2026-11-11"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ee:d2:c3:0a:99:a6:0b:f9:52:c3:2c:ac:4c:21:b6:23"
      )
}
