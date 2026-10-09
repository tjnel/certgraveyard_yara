import "pe"

rule MAL_Compromised_Cert_Unknown_Certum_748C413CBC2B00678EBA0E038B765A2D {
   meta:
      description         = "Detects Unknown with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-31"
      version             = "1.0"

      hash                = "7ec51b173c7d313164fc0603cf8e234e52e0d708abd0b73a9175f26913bf72a8"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PengXueWu"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "74:8c:41:3c:bc:2b:00:67:8e:ba:0e:03:8b:76:5a:2d"
      cert_thumbprint     = "e6c90fb3a49f994119c2b90a4cc1dc32c417ab44"
      cert_valid_from     = "2026-07-31"
      cert_valid_to       = "2027-07-31"

      country             = "CN"
      state               = "云南省"
      locality            = "普洱市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "74:8c:41:3c:bc:2b:00:67:8e:ba:0e:03:8b:76:5a:2d"
      )
}
