import "pe"

rule MAL_Compromised_Cert_UNK_50_SSL_com_51D6F6F3329863D25B0544C84A5F409 {
   meta:
      description         = "Detects UNK-50 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-29"
      version             = "1.0"

      hash                = "d16df70a1da634ab0e157b22dc69c6c05053591d5b05413fe3590bc0037ae374"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Krystal Clark"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "51:d6:f6:f3:32:98:63:d2:5b:05:44:c8:4a:5f:40:9"
      cert_thumbprint     = "cc40035c8fb92325c9ba8524bf00eb0604f2ad45"
      cert_valid_from     = "2026-10-29"
      cert_valid_to       = "2027-10-29"

      country             = "US"
      state               = "Ohio"
      locality            = "Belpre"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "51:d6:f6:f3:32:98:63:d2:5b:05:44:c8:4a:5f:40:9"
      )
}
