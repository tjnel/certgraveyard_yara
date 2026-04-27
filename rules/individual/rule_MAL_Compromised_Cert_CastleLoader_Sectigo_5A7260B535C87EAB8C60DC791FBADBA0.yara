import "pe"

rule MAL_Compromised_Cert_CastleLoader_Sectigo_5A7260B535C87EAB8C60DC791FBADBA0 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "dc06cf3983981f0996b24f8724a292bb2a401c7a57c33dff0ed88fb737dc54c9"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: bmwservicebestik[.]com"

      signer              = "ENGINEERING AND TECHNICAL PROCUREMENT SERVICES LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "5a:72:60:b5:35:c8:7e:ab:8c:60:dc:79:1f:ba:db:a0"
      cert_thumbprint     = "33B92801CAD416477349E00102AB74183AFA7867"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-04-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "5a:72:60:b5:35:c8:7e:ab:8c:60:dc:79:1f:ba:db:a0"
      )
}
