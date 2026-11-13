import "pe"

rule MAL_Compromised_Cert_FakeWallet_SSL_com_6C3EFF7D65CCF7EDD19774BD3C77F3A7 {
   meta:
      description         = "Detects FakeWallet with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-09"
      version             = "1.0"

      hash                = "e07733f7f88908ff3e0cab4e1c4061221deeb58cfb188d9de4affe79c92a99a2"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Kalkidan Bekele"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "6c:3e:ff:7d:65:cc:f7:ed:d1:97:74:bd:3c:77:f3:a7"
      cert_thumbprint     = "624d77b7636af52bf0ee5c2b719dc5c4f1e4cb12"
      cert_valid_from     = "2026-10-09"
      cert_valid_to       = "2027-10-09"

      country             = "US"
      state               = "Virginia"
      locality            = "Alexandria"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "6c:3e:ff:7d:65:cc:f7:ed:d1:97:74:bd:3c:77:f3:a7"
      )
}
