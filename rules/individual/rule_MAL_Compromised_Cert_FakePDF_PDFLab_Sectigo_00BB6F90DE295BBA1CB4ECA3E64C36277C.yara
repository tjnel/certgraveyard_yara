import "pe"

rule MAL_Compromised_Cert_FakePDF_PDFLab_Sectigo_00BB6F90DE295BBA1CB4ECA3E64C36277C {
   meta:
      description         = "Detects FakePDF, PDFLab with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-23"
      version             = "1.0"

      hash                = "49a66a4e5627fb53c56eaae62054a7a9fb2cb736f8ddea735ad18a8f1244a9c7"
      malware             = "FakePDF, PDFLab"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BYTESPROUT LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA R36"
      cert_serial         = "00:bb:6f:90:de:29:5b:ba:1c:b4:ec:a3:e6:4c:36:27:7c"
      cert_thumbprint     = "1F031BD73D6B2F48C2B253C325AD5F6C987ED52D"
      cert_valid_from     = "2026-03-23"
      cert_valid_to       = "2027-06-21"

      country             = "GB"
      state               = "London"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA R36" and
         sig.serial == "00:bb:6f:90:de:29:5b:ba:1c:b4:ec:a3:e6:4c:36:27:7c"
      )
}
