import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_SSL_com_115422DA20E07633305632A5889BAD37 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-11"
      version             = "1.0"

      hash                = "dc316b573b096ec3972c6741079d886a47f22aa057b4fa457ceb3e4268efd5d4"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Ready 2 Fix, Inc"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "11:54:22:da:20:e0:76:33:30:56:32:a5:88:9b:ad:37"
      cert_thumbprint     = "2aaf6352bd307d14cdb4ce7040df19ecdcead41f"
      cert_valid_from     = "2026-11-11"
      cert_valid_to       = "2027-11-11"

      country             = "US"
      state               = "Georgia"
      locality            = "Alpharetta"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "11:54:22:da:20:e0:76:33:30:56:32:a5:88:9b:ad:37"
      )
}
