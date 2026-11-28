import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_3300066F3D4DD2FF2060D6901B000000066F3D {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-18"
      version             = "1.0"

      hash                = "69dfe28b89de0bfb653b9a7e081d2f77e08ceab7613d15003089e7193d300b91"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Essie Sound"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:06:6f:3d:4d:d2:ff:20:60:d6:90:1b:00:00:00:06:6f:3d"
      cert_thumbprint     = "609488fb24dcc13e48aac9c771906561f41d6915"
      cert_valid_from     = "2026-09-18"
      cert_valid_to       = "2026-09-21"

      country             = "NL"
      state               = "Friesland"
      locality            = "Heerenveen"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:06:6f:3d:4d:d2:ff:20:60:d6:90:1b:00:00:00:06:6f:3d"
      )
}
