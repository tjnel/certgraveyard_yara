import "pe"

rule MAL_Compromised_Cert_ScreenConnect_Loader_SSL_com_2AB994AA02E70B768CC8984814BD8F41 {
   meta:
      description         = "Detects ScreenConnect Loader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-09"
      version             = "1.0"

      hash                = "71b04e2d36fef06e17baafe2fd1ace5534bfc466b15f10495bc310e50bec972a"
      malware             = "ScreenConnect Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Brittnay Hooper"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "2a:b9:94:aa:02:e7:0b:76:8c:c8:98:48:14:bd:8f:41"
      cert_thumbprint     = "5afaeff1eabef55eaf9c28a7be35f40a70d7e5a7"
      cert_valid_from     = "2026-07-09"
      cert_valid_to       = "2027-07-09"

      country             = "US"
      state               = "Texas"
      locality            = "Humble"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "2a:b9:94:aa:02:e7:0b:76:8c:c8:98:48:14:bd:8f:41"
      )
}
