import "pe"

rule MAL_Compromised_Cert_FakeRMM_SSL_com_09867A82C28DB37CDBEC2A426D6B528E {
   meta:
      description         = "Detects FakeRMM with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-01"
      version             = "1.0"

      hash                = "d8a4361786c81cb9fdf83140bbb1e09500f8bfee9c3193935347ce574a5c71f2"
      malware             = "FakeRMM"
      malware_type        = "Unknown"
      malware_notes       = "Fake MSTeams and Docusign leading to \"VoidDrift\" RMM tool"

      signer              = "Laservue Eye Center, Medical Corporation"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "09:86:7a:82:c2:8d:b3:7c:db:ec:2a:42:6d:6b:52:8e"
      cert_thumbprint     = "9C55811B381A2C9128FA4D80D8E1C5A1BE9459D6"
      cert_valid_from     = "2025-12-01"
      cert_valid_to       = "2026-11-30"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "09:86:7a:82:c2:8d:b3:7c:db:ec:2a:42:6d:6b:52:8e"
      )
}
