import "pe"

rule MAL_Compromised_Cert_TamperedChef_Sectigo_454981B689399CF22E25587C243C3311 {
   meta:
      description         = "Detects TamperedChef with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-13"
      version             = "1.0"

      hash                = "c37a22fa29e84996d5110d8887ee32905ab318e43d5a785120be5bbe5ea58062"
      malware             = "TamperedChef"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Binary Wave Innovations LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "45:49:81:b6:89:39:9c:f2:2e:25:58:7c:24:3c:33:11"
      cert_thumbprint     = "a10776d0715c969ae5fbea057d1271c316705e98"
      cert_valid_from     = "2026-02-13"
      cert_valid_to       = "2027-02-13"

      country             = "UA"
      state               = "Kyiv"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "45:49:81:b6:89:39:9c:f2:2e:25:58:7c:24:3c:33:11"
      )
}
