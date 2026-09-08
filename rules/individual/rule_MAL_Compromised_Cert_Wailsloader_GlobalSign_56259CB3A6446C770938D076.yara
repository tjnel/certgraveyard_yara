import "pe"

rule MAL_Compromised_Cert_Wailsloader_GlobalSign_56259CB3A6446C770938D076 {
   meta:
      description         = "Detects Wailsloader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "9ba0779e868f29ffb1738ff2f95b9bb18951527ff3283b8dff20ef2896448259"
      malware             = "Wailsloader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Fast Home Group Limited Liability Company"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "56:25:9c:b3:a6:44:6c:77:09:38:d0:76"
      cert_thumbprint     = "b2b039cbf48d8edece4d9b4ae8a0dc436447d0a8"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-03-24"

      country             = "KG"
      state               = "Osh"
      locality            = "Osh"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "56:25:9c:b3:a6:44:6c:77:09:38:d0:76"
      )
}
