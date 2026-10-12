import "pe"

rule MAL_Compromised_Cert_ChainScript_Certum_1575AA28624E4EE4704303DD356D8ED1 {
   meta:
      description         = "Detects ChainScript with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-25"
      version             = "1.0"

      hash                = "29834c1a0bb5ebbbfe20bee53fb3694df010af8a02aa2cb7f39e08eff1c6896c"
      malware             = "ChainScript"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Pelican Finland Holding Oy"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "15:75:aa:28:62:4e:4e:e4:70:43:03:dd:35:6d:8e:d1"
      cert_thumbprint     = "d9c26f3467740c4eca2ab754404bd5e26a5d4357"
      cert_valid_from     = "2026-08-25"
      cert_valid_to       = "2027-08-25"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "15:75:aa:28:62:4e:4e:e4:70:43:03:dd:35:6d:8e:d1"
      )
}
