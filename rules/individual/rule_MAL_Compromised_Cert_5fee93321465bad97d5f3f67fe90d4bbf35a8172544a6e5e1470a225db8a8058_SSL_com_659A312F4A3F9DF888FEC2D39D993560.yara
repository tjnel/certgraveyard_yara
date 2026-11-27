import "pe"

rule MAL_Compromised_Cert_5fee93321465bad97d5f3f67fe90d4bbf35a8172544a6e5e1470a225db8a8058_SSL_com_659A312F4A3F9DF888FEC2D39D993560 {
   meta:
      description         = "Detects 5fee93321465bad97d5f3f67fe90d4bbf35a8172544a6e5e1470a225db8a8058 with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-04"
      version             = "1.0"

      hash                = "5fee93321465bad97d5f3f67fe90d4bbf35a8172544a6e5e1470a225db8a8058"
      malware             = "5fee93321465bad97d5f3f67fe90d4bbf35a8172544a6e5e1470a225db8a8058"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INLINE SOFTWARE ANS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "65:9a:31:2f:4a:3f:9d:f8:88:fe:c2:d3:9d:99:35:60"
      cert_thumbprint     = "3ae048f6b77a565ad88601b86d8c4e249ba03819"
      cert_valid_from     = "2026-06-04"
      cert_valid_to       = "2027-06-04"

      country             = "NO"
      state               = "Oslo"
      locality            = "Oslo"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "65:9a:31:2f:4a:3f:9d:f8:88:fe:c2:d3:9d:99:35:60"
      )
}
