import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_5168CE37CEED23752B869467676FC30D {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-05"
      version             = "1.0"

      hash                = "80a88e46054917be370301563491447e43a8b8a7229983a1ff534dff30c7979e"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Osh Spetsstroy LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "51:68:ce:37:ce:ed:23:75:2b:86:94:67:67:6f:c3:0d"
      cert_thumbprint     = "AB46CF19EDCCF2357D9F5D7696DD24ECA52EC3ED"
      cert_valid_from     = "2026-06-05"
      cert_valid_to       = "2027-06-05"

      country             = "KG"
      state               = "Osh"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "163181-3306-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "51:68:ce:37:ce:ed:23:75:2b:86:94:67:67:6f:c3:0d"
      )
}
