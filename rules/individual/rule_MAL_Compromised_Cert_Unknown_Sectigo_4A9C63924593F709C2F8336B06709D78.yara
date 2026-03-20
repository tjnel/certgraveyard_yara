import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_4A9C63924593F709C2F8336B06709D78 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-10-08"
      version             = "1.0"

      hash                = "e75bcf0d9d5684f1dd7ba517d6158517edf2534e533c7bd54ef53ecebd068b35"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Pulse Drift Media LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "4a:9c:63:92:45:93:f7:09:c2:f8:33:6b:06:70:9d:78"
      cert_thumbprint     = "82EEA41960AC840E8270CE9146D0CA1E793CC79E"
      cert_valid_from     = "2025-10-08"
      cert_valid_to       = "2026-10-08"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "4a:9c:63:92:45:93:f7:09:c2:f8:33:6b:06:70:9d:78"
      )
}
