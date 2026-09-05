import "pe"

rule MAL_Compromised_Cert_Certificate_warming_Certum_19DBCE4E308A2479A8796E6AFAB9B7D8 {
   meta:
      description         = "Detects Certificate warming with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-13"
      version             = "1.0"

      hash                = "1a54e8eaba82f1c52bbccb8e37078d14291204f7732e24ba8b2449f24853e9a0"
      malware             = "Certificate warming"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Code Beyond d.o.o."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "19:db:ce:4e:30:8a:24:79:a8:79:6e:6a:fa:b9:b7:d8"
      cert_thumbprint     = "4f0e771c06c76b919e13c3770fc78e2a9f05c9bc"
      cert_valid_from     = "2026-08-13"
      cert_valid_to       = "2027-08-13"

      country             = "HR"
      state               = "Grad Zagreb"
      locality            = "Zagreb"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "19:db:ce:4e:30:8a:24:79:a8:79:6e:6a:fa:b9:b7:d8"
      )
}
