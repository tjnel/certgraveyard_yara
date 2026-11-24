import "pe"

rule MAL_Compromised_Cert_PDFizer_Sectigo_11D997F2C3AE3D81619C384DEAF8F970 {
   meta:
      description         = "Detects PDFizer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-10"
      version             = "1.0"

      hash                = "3650c2a39a90173b234ad04378b2c42cd34ab6a02a6bd6e5c22a79a16e2b89d9"
      malware             = "PDFizer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Muhammad Awais"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "11:d9:97:f2:c3:ae:3d:81:61:9c:38:4d:ea:f8:f9:70"
      cert_thumbprint     = "52202cf782fa9ed0b95d9e790fe434ab09d7f4ea"
      cert_valid_from     = "2026-09-10"
      cert_valid_to       = "2027-09-10"

      country             = "PK"
      state               = "Punjab"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "11:d9:97:f2:c3:ae:3d:81:61:9c:38:4d:ea:f8:f9:70"
      )
}
