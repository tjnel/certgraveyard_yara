import "pe"

rule MAL_Compromised_Cert_WailsLoader_Certum_1575AA28624E4EE4704303DD356D8ED1 {
   meta:
      description         = "Detects WailsLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-25"
      version             = "1.0"

      hash                = "d4bb1f9cc14e1a27aa5d4f5ec397247b06cc5b0ae0b8fd4067a2b10f6223e2ef"
      malware             = "WailsLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Pelican Finland Holding Oy"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "15:75:aa:28:62:4e:4e:e4:70:43:03:dd:35:6d:8e:d1"
      cert_thumbprint     = "2c1b0ba0a2d0eccd7554fb53a7e80d223b156c28dff8185f362e88a63b362c15"
      cert_valid_from     = "2026-08-25"
      cert_valid_to       = "2027-08-25"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "Helsinki"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "15:75:aa:28:62:4e:4e:e4:70:43:03:dd:35:6d:8e:d1"
      )
}
