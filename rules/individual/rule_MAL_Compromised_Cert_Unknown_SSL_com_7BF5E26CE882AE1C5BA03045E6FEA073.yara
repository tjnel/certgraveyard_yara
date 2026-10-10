import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_7BF5E26CE882AE1C5BA03045E6FEA073 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-01"
      version             = "1.0"

      hash                = "1437ba3685c2b5ad95a3e09c47c2dee0e3adf3aa3b4a11f425a14d0631d4c9c0"
      malware             = "Unknown"
      malware_type        = "Backdoor"
      malware_notes       = ""

      signer              = "Ezequias Isai Fernandez Cantarero"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "7b:f5:e2:6c:e8:82:ae:1c:5b:a0:30:45:e6:fe:a0:73"
      cert_thumbprint     = "24f336983285496bf9116481c7a2e68c1adedaf9"
      cert_valid_from     = "2026-07-01"
      cert_valid_to       = "2027-07-01"

      country             = "US"
      state               = "Texas"
      locality            = "Pasadena"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "7b:f5:e2:6c:e8:82:ae:1c:5b:a0:30:45:e6:fe:a0:73"
      )
}
