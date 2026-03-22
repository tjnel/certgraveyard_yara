import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_1354107DF674025F1F24B8CFB01AAEC3 {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-09-30"
      version             = "1.0"

      hash                = "ef5037d0c61441c4dc532452cdc89019a53a1a12e2693482e2d7fae325b6adc4"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Fake meeting software targeting crypto users worldwide"

      signer              = "MATRIKULA LTD"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "13:54:10:7d:f6:74:02:5f:1f:24:b8:cf:b0:1a:ae:c3"
      cert_thumbprint     = "34D1489DA06EBB5524CCF3A8D4BE8C1B5A7E6D9B"
      cert_valid_from     = "2025-09-30"
      cert_valid_to       = "2026-09-30"

      country             = "GB"
      state               = "???"
      locality            = "London"
      email               = "???"
      rdn_serial_number   = "16200073"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "13:54:10:7d:f6:74:02:5f:1f:24:b8:cf:b0:1a:ae:c3"
      )
}
