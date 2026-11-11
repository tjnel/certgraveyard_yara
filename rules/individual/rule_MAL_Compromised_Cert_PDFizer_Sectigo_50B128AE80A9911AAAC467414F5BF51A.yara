import "pe"

rule MAL_Compromised_Cert_PDFizer_Sectigo_50B128AE80A9911AAAC467414F5BF51A {
   meta:
      description         = "Detects PDFizer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-03"
      version             = "1.0"

      hash                = "58ef72c97c66fd8385b7e708c9f4f3a47abdb6baf402b821de0d194a5332b3d9"
      malware             = "PDFizer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Muhammad Ibrahim"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "50:b1:28:ae:80:a9:91:1a:aa:c4:67:41:4f:5b:f5:1a"
      cert_thumbprint     = "f01460af7ee7e12942896401eac47c7162f6dc10"
      cert_valid_from     = "2026-08-03"
      cert_valid_to       = "2027-08-03"

      country             = "PK"
      state               = "Punjab"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "50:b1:28:ae:80:a9:91:1a:aa:c4:67:41:4f:5b:f5:1a"
      )
}
