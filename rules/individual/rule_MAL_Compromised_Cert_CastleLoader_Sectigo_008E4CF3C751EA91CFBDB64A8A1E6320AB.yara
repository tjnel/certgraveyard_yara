import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_008E4CF3C751EA91CFBDB64A8A1E6320AB {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-03"
      version             = "1.0"

      hash                = "edea1565c4c0fde5a036fbe73525e180983bb0a67d1fed6bb846b9ab8cecd7db"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: shopretailbmw[.]com"

      signer              = "Frozen Assets Ice Company, LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:8e:4c:f3:c7:51:ea:91:cf:bd:b6:4a:8a:1e:63:20:ab"
      cert_thumbprint     = "FD8D2F469DCC232281FFD4AC6B3C0A088DA1ACE8"
      cert_valid_from     = "2026-04-03"
      cert_valid_to       = "2027-04-03"

      country             = "US"
      state               = "Arizona"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "L12101683"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:8e:4c:f3:c7:51:ea:91:cf:bd:b6:4a:8a:1e:63:20:ab"
      )
}
