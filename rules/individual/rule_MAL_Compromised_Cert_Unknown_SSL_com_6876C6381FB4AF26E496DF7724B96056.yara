import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_6876C6381FB4AF26E496DF7724B96056 {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-28"
      version             = "1.0"

      hash                = "14964a27f6b34740473510f858f2b46ac0830a87dd5ee8a19b80fb469c042bbb"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "REDPOINT SOFTWARE ANS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "68:76:c6:38:1f:b4:af:26:e4:96:df:77:24:b9:60:56"
      cert_thumbprint     = ""
      cert_valid_from     = "2026-05-28"
      cert_valid_to       = "2027-05-28"

      country             = "NO"
      state               = "Trondelag"
      locality            = "Klaebu"
      email               = ""
      rdn_serial_number   = "---"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "68:76:c6:38:1f:b4:af:26:e4:96:df:77:24:b9:60:56"
      )
}
