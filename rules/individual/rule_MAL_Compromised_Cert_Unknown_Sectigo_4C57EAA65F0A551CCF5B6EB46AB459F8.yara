import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_4C57EAA65F0A551CCF5B6EB46AB459F8 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-01"
      version             = "1.0"

      hash                = "89a63487a28ab7e99863c0160b73fd7931059124e0c3b944c40b999769a7b6a0"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tropical RIiff Ltd"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "4c:57:ea:a6:5f:0a:55:1c:cf:5b:6e:b4:6a:b4:59:f8"
      cert_thumbprint     = "112A2987C140633DD202A24C1604C16C47A405BA"
      cert_valid_from     = "2025-12-01"
      cert_valid_to       = "2026-12-01"

      country             = "IL"
      state               = "Central"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "517108411"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "4c:57:ea:a6:5f:0a:55:1c:cf:5b:6e:b4:6a:b4:59:f8"
      )
}
