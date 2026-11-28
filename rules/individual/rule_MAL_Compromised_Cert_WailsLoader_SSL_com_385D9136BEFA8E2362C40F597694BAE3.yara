import "pe"

rule MAL_Compromised_Cert_WailsLoader_SSL_com_385D9136BEFA8E2362C40F597694BAE3 {
   meta:
      description         = "Detects WailsLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-17"
      version             = "1.0"

      hash                = "caa5f261356779e7df52444d0f1096eb3916ebef4d6ee6461361043f00d788a3"
      malware             = "WailsLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "INTER LAGER BOX d.o.o."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "38:5d:91:36:be:fa:8e:23:62:c4:0f:59:76:94:ba:e3"
      cert_thumbprint     = "7ec1c51fece3275bc70de4ced2a093ac2f93f354"
      cert_valid_from     = "2026-11-17"
      cert_valid_to       = "2027-11-17"

      country             = "HR"
      state               = "---"
      locality            = "Zagreb"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "38:5d:91:36:be:fa:8e:23:62:c4:0f:59:76:94:ba:e3"
      )
}
