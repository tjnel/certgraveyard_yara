import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_3A33265796F807181E9FDD677AFE786A {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-06"
      version             = "1.0"

      hash                = "1162457ce6539b56e7784f961db4d4f7cef42f9ac1b3232c1656b6534fed9917"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Avento Software OU"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "3a:33:26:57:96:f8:07:18:1e:9f:dd:67:7a:fe:78:6a"
      cert_thumbprint     = "732461225693C36AECDC721F0204933D1D3ADC4D"
      cert_valid_from     = "2026-07-06"
      cert_valid_to       = "2027-07-06"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "3a:33:26:57:96:f8:07:18:1e:9f:dd:67:7a:fe:78:6a"
      )
}
