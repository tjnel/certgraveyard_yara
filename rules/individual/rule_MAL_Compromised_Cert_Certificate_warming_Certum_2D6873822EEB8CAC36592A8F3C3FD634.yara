import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Certum_2D6873822EEB8CAC36592A8F3C3FD634 {
   meta:
      description         = "Detects Certificate warming with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-18"
      version             = "1.0"

      hash                = "e8ee48d5a7c6f7773aafa2350ec4c07502efc5201ac6a2949f505d243f7308da"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = "This certificate is being used to sign benign files to \"warm\" the certificate to give it a higher reputation before signing malicious files."

      signer              = "HORECA tech d.o.o."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "2d:68:73:82:2e:eb:8c:ac:36:59:2a:8f:3c:3f:d6:34"
      cert_thumbprint     = "C488A1827E068000BA35FCA01465E8BD49FA7C05"
      cert_valid_from     = "2026-06-18"
      cert_valid_to       = "2027-06-18"

      country             = "HR"
      state               = "Grad Zagreb"
      locality            = "Zagreb"
      email               = "???"
      rdn_serial_number   = "081408314"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "2d:68:73:82:2e:eb:8c:ac:36:59:2a:8f:3c:3f:d6:34"
      )
}
