import "pe"

rule MAL_Compromised_Cert_WailsLoader_Sectigo_A092CC6E5FAB2CC168E1BEDC90C111B1 {
   meta:
      description         = "Detects WailsLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-21"
      version             = "1.0"

      hash                = "774c4dd4024edc3eab82d44adff302704f00ccfe5c5f669315ee1ea5094930c0"
      malware             = "WailsLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DESIGN COLOUR AS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "a0:92:cc:6e:5f:ab:2c:c1:68:e1:be:dc:90:c1:11:b1"
      cert_thumbprint     = "a2ba2b1d7c2453750abb98cbcc44199b76d0edc1"
      cert_valid_from     = "2026-10-21"
      cert_valid_to       = "2027-10-21"

      country             = "NO"
      state               = "Oslo"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "a0:92:cc:6e:5f:ab:2c:c1:68:e1:be:dc:90:c1:11:b1"
      )
}
