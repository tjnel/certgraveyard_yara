import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_6E35C09D6FBFE2E0D4A2B1741B6CD5BD {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-18"
      version             = "1.0"

      hash                = "2c98d6524f1156506277e137c59e41aea9ceffc7b574b5272f6f58e80955d179"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Amerra Finland Oy"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "6e:35:c0:9d:6f:bf:e2:e0:d4:a2:b1:74:1b:6c:d5:bd"
      cert_thumbprint     = "0EC0DCCB150E4A78A9A938101AEC9F534949F964"
      cert_valid_from     = "2026-06-18"
      cert_valid_to       = "2027-06-18"

      country             = "FI"
      state               = "Pohjois-savo"
      locality            = "Kuopio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "6e:35:c0:9d:6f:bf:e2:e0:d4:a2:b1:74:1b:6c:d5:bd"
      )
}
