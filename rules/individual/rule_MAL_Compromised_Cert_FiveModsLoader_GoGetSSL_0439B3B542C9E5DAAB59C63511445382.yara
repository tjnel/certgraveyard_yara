import "pe"

rule MAL_Compromised_Cert_FiveModsLoader_GoGetSSL_0439B3B542C9E5DAAB59C63511445382 {
   meta:
      description         = "Detects FiveModsLoader with compromised cert (GoGetSSL)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-21"
      version             = "1.0"

      hash                = "0c934d4d04bbbd163e8a43eee5db54d80a8578753f0c5a1884c3bca9e9355217"
      malware             = "FiveModsLoader"
      malware_type        = "Backdoor"
      malware_notes       = ""

      signer              = "Danylo Babenko"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "04:39:b3:b5:42:c9:e5:da:ab:59:c6:35:11:44:53:82"
      cert_thumbprint     = "914F0440019327E71BF233E7E1C8E2BE1A16CD50"
      cert_valid_from     = "2026-03-21"
      cert_valid_to       = "2027-03-20"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "04:39:b3:b5:42:c9:e5:da:ab:59:c6:35:11:44:53:82"
      )
}
