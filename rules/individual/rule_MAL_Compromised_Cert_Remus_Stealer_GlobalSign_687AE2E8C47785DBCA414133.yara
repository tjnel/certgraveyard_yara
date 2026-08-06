import "pe"

rule MAL_Compromised_Cert_Remus_Stealer_GlobalSign_687AE2E8C47785DBCA414133 {
   meta:
      description         = "Detects Remus Stealer with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-09"
      version             = "1.0"

      hash                = "3c6b036f2eebc124c17db51960d9f6c9b39e236e9a33d5ac0c3a3a2cabe36833"
      malware             = "Remus Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DESIGN COLOUR AS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "68:7a:e2:e8:c4:77:85:db:ca:41:41:33"
      cert_thumbprint     = "8e24ce3ab4f567f1701b80d97873036ec692b40b"
      cert_valid_from     = "2026-04-09"
      cert_valid_to       = "2027-04-10"

      country             = "NO"
      state               = "Oslo"
      locality            = "Oslo"
      email               = "info@riksmal.net"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "68:7a:e2:e8:c4:77:85:db:ca:41:41:33"
      )
}
