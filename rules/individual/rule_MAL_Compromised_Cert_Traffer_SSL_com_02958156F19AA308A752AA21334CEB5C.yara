import "pe"

rule MAL_Compromised_Cert_Traffer_SSL_com_02958156F19AA308A752AA21334CEB5C {
   meta:
      description         = "Detects Traffer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-14"
      version             = "1.0"

      hash                = "e0b089598582d3a4ab3831a54203ec39526bd12ff10e5709056cf854280d4800"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Fast Home Group LLC"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "02:95:81:56:f1:9a:a3:08:a7:52:aa:21:33:4c:eb:5c"
      cert_thumbprint     = "9F4C05AC53A52D9645E2E295ADD7AC6315AFFAB5"
      cert_valid_from     = "2026-04-14"
      cert_valid_to       = "2027-04-14"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "02:95:81:56:f1:9a:a3:08:a7:52:aa:21:33:4c:eb:5c"
      )
}
