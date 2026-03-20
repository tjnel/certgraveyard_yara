import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00A17E0D68EA949320B5EA0BB0F28A3FB6 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-30"
      version             = "1.0"

      hash                = "4ed12571df78e99c6e9daabc893766ab059036f9ce65ffc9eef450c5a5a1f3e2"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ice Ignite LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a1:7e:0d:68:ea:94:93:20:b5:ea:0b:b0:f2:8a:3f:b6"
      cert_thumbprint     = "E1BB445DF62E7F30F7F2AB94F5C7C5F0C3183D28"
      cert_valid_from     = "2025-12-30"
      cert_valid_to       = "2026-12-30"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a1:7e:0d:68:ea:94:93:20:b5:ea:0b:b0:f2:8a:3f:b6"
      )
}
