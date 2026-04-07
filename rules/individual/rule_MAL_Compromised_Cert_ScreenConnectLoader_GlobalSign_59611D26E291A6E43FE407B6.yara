import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_GlobalSign_59611D26E291A6E43FE407B6 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-30"
      version             = "1.0"

      hash                = "d6c8bdd4e8b6d64f619c0277b26fa68c6117dae36bb9a3707b4d89d4a88e343a"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Compare Financial and Internet Services GmbH"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "59:61:1d:26:e2:91:a6:e4:3f:e4:07:b6"
      cert_thumbprint     = "6B321BFAC3284E564933B014FEE3214FFFD76790"
      cert_valid_from     = "2026-03-30"
      cert_valid_to       = "2027-03-31"

      country             = "AT"
      state               = "Wien"
      locality            = "Wien"
      email               = "???"
      rdn_serial_number   = "283786h"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "59:61:1d:26:e2:91:a6:e4:3f:e4:07:b6"
      )
}
