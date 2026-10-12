import "pe"

rule MAL_Compromised_Cert_Certificate_warming_GoGetSSL_68D2D2FA79B283FE8E193CAE31CB5A3 {
   meta:
      description         = "Detects Certificate warming with compromised cert (GoGetSSL)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-10"
      version             = "1.0"

      hash                = "3c501a1886da3229d12b2170ee1afd84da46cbbb3dd36ed01fab8051b911c617"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = "This certificate is being used on legitimate software either as certificate warming or a precursor to trojanized payloads."

      signer              = "Pelican Finland Holding Oy"
      cert_issuer_short   = "GoGetSSL"
      cert_issuer         = "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1"
      cert_serial         = "68:d2:d2:fa:79:b2:83:fe:8e:19:3c:ae:31:cb:5a:3"
      cert_thumbprint     = "36a15b21bbf3ad7ba351d9f2238d2a08bb384f3b"
      cert_valid_from     = "2026-09-10"
      cert_valid_to       = "2027-09-09"

      country             = "FI"
      state               = "---"
      locality            = "Helsinki"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GoGetSSL G4 CS RSA4096 SHA256 2022 CA-1" and
         sig.serial == "68:d2:d2:fa:79:b2:83:fe:8e:19:3c:ae:31:cb:5a:3"
      )
}
