import "pe"

rule MAL_Compromised_Cert_CrocoRAT_SSL_com_2BFF385A538994844803B05524BFFBB0 {
   meta:
      description         = "Detects CrocoRAT with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-10"
      version             = "1.0"

      hash                = "907da6987c3fd2115fd62c8dbcba9837cbdeb8dd00851265c601a93261184343"
      malware             = "CrocoRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JB Alpha Digital"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "2b:ff:38:5a:53:89:94:84:48:03:b0:55:24:bf:fb:b0"
      cert_thumbprint     = ""
      cert_valid_from     = "2025-09-10"
      cert_valid_to       = "2026-09-09"

      country             = "SE"
      state               = "Stockholm County"
      locality            = "Danderyds Kommun"
      email               = ""
      rdn_serial_number   = "---"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "2b:ff:38:5a:53:89:94:84:48:03:b0:55:24:bf:fb:b0"
      )
}
