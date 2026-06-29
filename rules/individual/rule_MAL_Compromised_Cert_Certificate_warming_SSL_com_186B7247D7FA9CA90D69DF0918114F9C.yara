import "pe"

rule MAL_Compromised_Cert_Certificate_warming_SSL_com_186B7247D7FA9CA90D69DF0918114F9C {
   meta:
      description         = "Detects Certificate warming with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-04"
      version             = "1.0"

      hash                = "debd4c4ceec31712bc1d2311020ee7626f9daf15f96989fdc32056156a63c495"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MK GRAND STROI, OSOO"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "18:6b:72:47:d7:fa:9c:a9:0d:69:df:09:18:11:4f:9c"
      cert_thumbprint     = "5E708DA17284C5CB67F1ABD883E2647A8640009C"
      cert_valid_from     = "2026-06-04"
      cert_valid_to       = "2027-06-04"

      country             = "KG"
      state               = "Osh Region"
      locality            = "Osh"
      email               = "???"
      rdn_serial_number   = "168457-3310-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "18:6b:72:47:d7:fa:9c:a9:0d:69:df:09:18:11:4f:9c"
      )
}
