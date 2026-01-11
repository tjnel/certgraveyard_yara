import "pe"

rule MAL_Compromised_Cert_Oddysey_Stealer_Apple_5D02F7C79213CBE0 {
   meta:
      description         = "Detects Oddysey Stealer with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-21"
      version             = "1.0"

      hash                = "1bcba93c7626a8b7b974737627d33d883836f1f6e5462d61dbfb0792463ad199"
      malware             = "Oddysey Stealer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Mireille Drapeau"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "5d:02:f7:c7:92:13:cb:e0"
      cert_thumbprint     = "870A3A44E5954DAAE50E9E5A90DC08499CB4200F"
      cert_valid_from     = "2025-12-21"
      cert_valid_to       = "2027-02-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "5d:02:f7:c7:92:13:cb:e0"
      )
}
