import "pe"

rule MAL_Compromised_Cert_BaoLoader_SSL_com_28C7E66012DAB05A4A953D88F185ED2C {
   meta:
      description         = "Detects BaoLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-24"
      version             = "1.0"

      hash                = "71edb9f9f757616fe62a49f2d5b55441f91618904517337abd9d0725b07c2a51"
      malware             = "BaoLoader"
      malware_type        = "Trojan"
      malware_notes       = ""

      signer              = "GLINT SOFTWARE SDN. BHD."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "28:c7:e6:60:12:da:b0:5a:4a:95:3d:88:f1:85:ed:2c"
      cert_thumbprint     = "99201EEE9807D24851026A8E8884E4C40245FAC7"
      cert_valid_from     = "2025-04-24"
      cert_valid_to       = "2026-04-24"

      country             = "MY"
      state               = "Johor"
      locality            = "Skudai"
      email               = "???"
      rdn_serial_number   = "???"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "28:c7:e6:60:12:da:b0:5a:4a:95:3d:88:f1:85:ed:2c"
      )
}
