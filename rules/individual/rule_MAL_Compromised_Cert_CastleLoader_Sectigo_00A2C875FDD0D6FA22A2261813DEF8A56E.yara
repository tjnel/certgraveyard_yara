import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_00A2C875FDD0D6FA22A2261813DEF8A56E {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "4ba0d3ae41a0ae3143e8c2c3307c24b0d548593f97c79a30c0387b3d62504c31"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SERPENTINE SOLAR LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a2:c8:75:fd:d0:d6:fa:22:a2:26:18:13:de:f8:a5:6e"
      cert_thumbprint     = "7C4FEFB8B9F931FABED24341AFF9462B68A63027"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-04-01"

      country             = "IE"
      state               = "Dublin"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "556711"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a2:c8:75:fd:d0:d6:fa:22:a2:26:18:13:de:f8:a5:6e"
      )
}
