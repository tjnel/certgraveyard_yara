import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_237DD9C69CE233B0CF24AA24AA803DA4 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-07"
      version             = "1.0"

      hash                = "adf0957559b8914b125ef263959f2882481df3b5dd0472888bf07e4e455a5d34"
      malware             = "Unknown"
      malware_type        = "Backdoor"
      malware_notes       = ""

      signer              = "Barbaros Cetinkaya"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "23:7d:d9:c6:9c:e2:33:b0:cf:24:aa:24:aa:80:3d:a4"
      cert_thumbprint     = "be64832b8f071014568014727bdfe0e9e4ce6f0b"
      cert_valid_from     = "2025-08-07"
      cert_valid_to       = "2026-08-07"

      country             = "DE"
      state               = "Bavaria"
      locality            = "Stein"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "23:7d:d9:c6:9c:e2:33:b0:cf:24:aa:24:aa:80:3d:a4"
      )
}
