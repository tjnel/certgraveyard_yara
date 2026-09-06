import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_184AF3D177711EAC2C281DE26E44F41B {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-24"
      version             = "1.0"

      hash                = "9f6314a4cdb784ce153e1bddc8488d4d20f59b7ec4c6cfc189a4bbb403d9cc61"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "File dropped by KongTuke Click-Fix lure."

      signer              = "PROGRAMVARE PARTNER ANS"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "18:4a:f3:d1:77:71:1e:ac:2c:28:1d:e2:6e:44:f4:1b"
      cert_thumbprint     = "aa221d145b51d569a640f3cb9f6208b96b21efa7"
      cert_valid_from     = "2026-08-24"
      cert_valid_to       = "2027-08-24"

      country             = "NO"
      state               = "---"
      locality            = "Manger"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "18:4a:f3:d1:77:71:1e:ac:2c:28:1d:e2:6e:44:f4:1b"
      )
}
