import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_63CA758ADC388C2C35EDFFBE86591A55 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-03"
      version             = "1.0"

      hash                = "2e775b4d6e08d393d45eef272df92ad173ead4d8dd20a5df36b6ea906f19c7bd"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Wuhan Liansitong Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "63:ca:75:8a:dc:38:8c:2c:35:ed:ff:be:86:59:1a:55"
      cert_thumbprint     = "5098F94DE882260DB79FBAA9C389676F9D58F059"
      cert_valid_from     = "2025-10-03"
      cert_valid_to       = "2026-10-03"

      country             = "CN"
      state               = "Hubei Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91420100MA7M3NX92T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "63:ca:75:8a:dc:38:8c:2c:35:ed:ff:be:86:59:1a:55"
      )
}
