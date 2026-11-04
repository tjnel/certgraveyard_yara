import "pe"

rule MAL_Compromised_Cert_PDFizer_SSL_com_5226A47E8A783FB03F836ECB18C746DE {
   meta:
      description         = "Detects PDFizer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-17"
      version             = "1.0"

      hash                = "8882748b3e07de882e34ef819a6dc2cfc8d70d71594d7c0ca9c71725d2118cbd"
      malware             = "PDFizer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SEELIV (SMC-PRIVATE) LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "52:26:a4:7e:8a:78:3f:b0:3f:83:6e:cb:18:c7:46:de"
      cert_thumbprint     = "f7ee29bac157f5c5f2c46b20c43ebbf8eef323ec"
      cert_valid_from     = "2026-05-17"
      cert_valid_to       = "2027-03-17"

      country             = "PK"
      state               = "Punjab"
      locality            = "Multan"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "52:26:a4:7e:8a:78:3f:b0:3f:83:6e:cb:18:c7:46:de"
      )
}
