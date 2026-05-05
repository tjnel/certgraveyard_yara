import "pe"

rule MAL_Compromised_Cert_Unknown_SSL_com_41FC5D610B8907BD08584D356598097D {
   meta:
      description         = "Detects Unknown with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "a2d9d1ad3d8a618ca7c0125a3cd8e1afe36759f9ccfb4965aa48358408e9d051"
      malware             = "Unknown"
      malware_type        = "Loader"
      malware_notes       = "Binary written in Nim used infra-telemetry[.]com for C2"

      signer              = "X Grup Technology Tesis Yonetim Hizmetleri Ltd. Sti."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "41:fc:5d:61:0b:89:07:bd:08:58:4d:35:65:98:09:7d"
      cert_thumbprint     = "FAC94EADD346B79B562A1870F76C0DFBDAA3D3BD"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2027-03-31"

      country             = "TR"
      state               = "Istanbul"
      locality            = "Kâğıthane"
      email               = "???"
      rdn_serial_number   = "1117672"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "41:fc:5d:61:0b:89:07:bd:08:58:4d:35:65:98:09:7d"
      )
}
