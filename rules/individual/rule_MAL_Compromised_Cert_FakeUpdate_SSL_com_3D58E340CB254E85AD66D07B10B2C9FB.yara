import "pe"

rule MAL_Compromised_Cert_FakeUpdate_SSL_com_3D58E340CB254E85AD66D07B10B2C9FB {
   meta:
      description         = "Detects FakeUpdate with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-17"
      version             = "1.0"

      hash                = "1ad0b1284c9e452e2cc98d6262d4f3cae7d2962f73def71a25c6f3121c4f3fde"
      malware             = "FakeUpdate"
      malware_type        = "Unknown"
      malware_notes       = "C2: korsaka[.]fun"

      signer              = "SCYLA SOLUTION ONE SP Z O O"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "3d:58:e3:40:cb:25:4e:85:ad:66:d0:7b:10:b2:c9:fb"
      cert_thumbprint     = "CEFB2E3AD0FAD0DDE7B3AC237710C675CCF63A86"
      cert_valid_from     = "2026-03-17"
      cert_valid_to       = "2027-03-17"

      country             = "PL"
      state               = "???"
      locality            = "Slupsk"
      email               = "???"
      rdn_serial_number   = "0001225864"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "3d:58:e3:40:cb:25:4e:85:ad:66:d0:7b:10:b2:c9:fb"
      )
}
