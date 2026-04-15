import "pe"

rule MAL_Compromised_Cert_Vidar_SSL_com_594200D2EE47728E81FD8B8E1A70EC50 {
   meta:
      description         = "Detects Vidar with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-30"
      version             = "1.0"

      hash                = "08448b53f2d4027ca341d6a76bd307ee4c9309a2a60010c53f73ae2837737cef"
      malware             = "Vidar"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ATX AI Software Teknoloji Ticaret A. S."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "59:42:00:d2:ee:47:72:8e:81:fd:8b:8e:1a:70:ec:50"
      cert_thumbprint     = "20AD1EE141A0A5AD3F9F7B6867AF85C04943E72C"
      cert_valid_from     = "2026-03-30"
      cert_valid_to       = "2027-03-30"

      country             = "TR"
      state               = "Istanbul"
      locality            = "Fatih"
      email               = "???"
      rdn_serial_number   = "1028960"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "59:42:00:d2:ee:47:72:8e:81:fd:8b:8e:1a:70:ec:50"
      )
}
