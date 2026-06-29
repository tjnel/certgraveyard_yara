import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_33000059E1806B33EE40FADEA60000000059E1 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-15"
      version             = "1.0"

      hash                = "f963cc4150a2a50c16f14bab8573393521a36f96bf32ae9b8473ab4e141f6d40"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "KELLY SULLIVAN"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:59:e1:80:6b:33:ee:40:fa:de:a6:00:00:00:00:59:e1"
      cert_thumbprint     = "9872D0A9EC03E0A4B8D542E3D0A08E10AE17AA2C"
      cert_valid_from     = "2026-04-15"
      cert_valid_to       = "2026-04-18"

      country             = "US"
      state               = "Alaska"
      locality            = "WASILLA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:59:e1:80:6b:33:ee:40:fa:de:a6:00:00:00:00:59:e1"
      )
}
