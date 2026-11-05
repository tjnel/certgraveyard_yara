import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_6DBB6DD7243B97569D7EC15DAB2D1A10 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-27"
      version             = "1.0"

      hash                = "fbdcf1c1ef19a5bef2c9ca43b3685aa5dacd78b7b071a90ced67ead83b736fa7"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Melvin Jackson"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "6d:bb:6d:d7:24:3b:97:56:9d:7e:c1:5d:ab:2d:1a:10"
      cert_thumbprint     = "6ce6c6213247058b4a7f11ff70d75c7afa218fd8"
      cert_valid_from     = "2026-10-27"
      cert_valid_to       = "2027-10-27"

      country             = "US"
      state               = "Florida"
      locality            = "Orlando"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "6d:bb:6d:d7:24:3b:97:56:9d:7e:c1:5d:ab:2d:1a:10"
      )
}
