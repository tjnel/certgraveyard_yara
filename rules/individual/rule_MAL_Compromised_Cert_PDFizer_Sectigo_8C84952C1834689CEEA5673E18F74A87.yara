import "pe"

rule MAL_Compromised_Cert_PDFizer_Sectigo_8C84952C1834689CEEA5673E18F74A87 {
   meta:
      description         = "Detects PDFizer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-06"
      version             = "1.0"

      hash                = "c07e80f324b3e55a12d829b1c497f9c2d6a381d80bda147602adaa9c921661c0"
      malware             = "PDFizer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Nazia Riaz"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "8c:84:95:2c:18:34:68:9c:ee:a5:67:3e:18:f7:4a:87"
      cert_thumbprint     = "4c31094c6db3da4259843c3149910d2add8e2abb"
      cert_valid_from     = "2026-08-06"
      cert_valid_to       = "2027-08-06"

      country             = "PK"
      state               = "Punjab"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "8c:84:95:2c:18:34:68:9c:ee:a5:67:3e:18:f7:4a:87"
      )
}
