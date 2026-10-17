import "pe"

rule MAL_Compromised_Cert_WailsLoader_Certum_184AF3D177711EAC2C281DE26E44F41B {
   meta:
      description         = "Detects WailsLoader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-24"
      version             = "1.0"

      hash                = "89c1bb04e296b0084b118a07f80316b5f694d7460ab13afc216c5bacc787d236"
      malware             = "WailsLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PROGRAMVARE PARTNER ANS"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "18:4a:f3:d1:77:71:1e:ac:2c:28:1d:e2:6e:44:f4:1b"
      cert_thumbprint     = "b44af76f283b8761cee957375e610933f42c4a13c2559d0c506298206295597f"
      cert_valid_from     = "2026-08-24"
      cert_valid_to       = "2027-08-24"

      country             = "NO"
      state               = "???"
      locality            = "Manger"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "18:4a:f3:d1:77:71:1e:ac:2c:28:1d:e2:6e:44:f4:1b"
      )
}
