import "pe"

rule MAL_Compromised_Cert_Pulse_Browser_Sectigo_00E96F42F8386E061B97F3611CA55BD23F {
   meta:
      description         = "Detects Pulse Browser with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-14"
      version             = "1.0"

      hash                = "0533d7287570ea61cb6bf3700c6bc52d9ea759563d73fbca8d735f326d11861d"
      malware             = "Pulse Browser"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alabama Technology USA, LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:e9:6f:42:f8:38:6e:06:1b:97:f3:61:1c:a5:5b:d2:3f"
      cert_thumbprint     = "9443AE127B9F0FFED64603B42F177A1FE397116D"
      cert_valid_from     = "2026-04-14"
      cert_valid_to       = "2027-04-14"

      country             = "US"
      state               = "California"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "6310788"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:e9:6f:42:f8:38:6e:06:1b:97:f3:61:1c:a5:5b:d2:3f"
      )
}
