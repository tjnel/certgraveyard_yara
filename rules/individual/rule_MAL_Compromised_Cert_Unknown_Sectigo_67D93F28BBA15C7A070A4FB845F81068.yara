import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_67D93F28BBA15C7A070A4FB845F81068 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-17"
      version             = "1.0"

      hash                = "c67305dc8d58959ea09d38f31c8f5ee4893887a6c160f187e84ce8a7b18ca167"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Logos Aqua LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "67:d9:3f:28:bb:a1:5c:7a:07:0a:4f:b8:45:f8:10:68"
      cert_thumbprint     = "240DEFC57DEBA96223D2AFDFEC427A7C18FCBAEE"
      cert_valid_from     = "2025-12-17"
      cert_valid_to       = "2026-12-17"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "67:d9:3f:28:bb:a1:5c:7a:07:0a:4f:b8:45:f8:10:68"
      )
}
