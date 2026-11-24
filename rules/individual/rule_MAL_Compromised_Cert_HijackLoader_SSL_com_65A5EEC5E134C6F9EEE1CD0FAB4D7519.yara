import "pe"

rule MAL_Compromised_Cert_HijackLoader_SSL_com_65A5EEC5E134C6F9EEE1CD0FAB4D7519 {
   meta:
      description         = "Detects HijackLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-29"
      version             = "1.0"

      hash                = "29b848e8f0c4a045cc51ea61d84446f6b5a3ebc48997ef67974b067104d5f3a6"
      malware             = "HijackLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Christina Carroll"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "65:a5:ee:c5:e1:34:c6:f9:ee:e1:cd:0f:ab:4d:75:19"
      cert_thumbprint     = "859c784165556e8917901030b1551705de5443b0"
      cert_valid_from     = "2026-10-29"
      cert_valid_to       = "2027-10-29"

      country             = "US"
      state               = "North Carolina"
      locality            = "Princeton"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "65:a5:ee:c5:e1:34:c6:f9:ee:e1:cd:0f:ab:4d:75:19"
      )
}
