import "pe"

rule MAL_Compromised_Cert_UnknownLoader_SSL_com_11E603B92A63487D692AD9519A0382FE {
   meta:
      description         = "Detects UnknownLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-21"
      version             = "1.0"

      hash                = "2fff9050124362c9d495114b0ef265f9627ac021d2b696d50e7426ed0a7d6850"
      malware             = "UnknownLoader"
      malware_type        = "Loader"
      malware_notes       = "File was distributed to be side-loaded by a python executable but may have been in development at time of discovery. The intended encrypted payload is missing."

      signer              = "Oh Development"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "11:e6:03:b9:2a:63:48:7d:69:2a:d9:51:9a:03:82:fe"
      cert_thumbprint     = "0050B1DB2EADA95831252FD331912A77009944F5"
      cert_valid_from     = "2025-05-21"
      cert_valid_to       = "2026-05-21"

      country             = "FR"
      state               = "Île-de-France"
      locality            = "Louveciennes"
      email               = "???"
      rdn_serial_number   = "503 310 138"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "11:e6:03:b9:2a:63:48:7d:69:2a:d9:51:9a:03:82:fe"
      )
}
