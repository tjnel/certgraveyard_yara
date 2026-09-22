import "pe"

rule MAL_Compromised_Cert_FakeRMM_SSL_com_31618F4DCEC27DC87917A80F27A84C00 {
   meta:
      description         = "Detects FakeRMM with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-01"
      version             = "1.0"

      hash                = "b1ad3ec73c70425ad1a2ff8ea40e7045f86e9c0c14e45c032743fa80906ad3e7"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Laservue Eye Center, Medical Corporation"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "31:61:8f:4d:ce:c2:7d:c8:79:17:a8:0f:27:a8:4c:00"
      cert_thumbprint     = "ec6029d5eda8045f4a96105ee618df5e10cf078e"
      cert_valid_from     = "2025-12-01"
      cert_valid_to       = "2026-12-01"

      country             = "US"
      state               = "California"
      locality            = "San Francisco"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "31:61:8f:4d:ce:c2:7d:c8:79:17:a8:0f:27:a8:4c:00"
      )
}
