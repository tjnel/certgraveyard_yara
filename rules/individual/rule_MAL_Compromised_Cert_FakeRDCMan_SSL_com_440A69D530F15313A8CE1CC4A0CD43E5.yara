import "pe"

rule MAL_Compromised_Cert_FakeRDCMan_SSL_com_440A69D530F15313A8CE1CC4A0CD43E5 {
   meta:
      description         = "Detects FakeRDCMan with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-09"
      version             = "1.0"

      hash                = "e6086a80fe5521abd1a1f6329d33177a3b6f4e7f776d56a7418b551abb656107"
      malware             = "FakeRDCMan"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Programvare Partner ANS"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "44:0a:69:d5:30:f1:53:13:a8:ce:1c:c4:a0:cd:43:e5"
      cert_thumbprint     = "14da112d5f2910e9c8ca1012a092984d921a2409"
      cert_valid_from     = "2026-09-09"
      cert_valid_to       = "2027-09-09"

      country             = "NO"
      state               = "Vestland"
      locality            = "Manger"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "44:0a:69:d5:30:f1:53:13:a8:ce:1c:c4:a0:cd:43:e5"
      )
}
