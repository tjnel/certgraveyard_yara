import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_3300009AC5222ECE0F58876B41000000009AC5 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-29"
      version             = "1.0"

      hash                = "d3e52c02da188ac05436434c9401776b0a842386ada7aeabab4fae5cc64f8abd"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "SERPENTINE SOLAR LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:9a:c5:22:2e:ce:0f:58:87:6b:41:00:00:00:00:9a:c5"
      cert_thumbprint     = "84CC981BBE757A1F7E98F3B34D7EE4035E906A2E"
      cert_valid_from     = "2026-04-29"
      cert_valid_to       = "2026-05-02"

      country             = "IE"
      state               = "Dublin"
      locality            = "Dublin"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:9a:c5:22:2e:ce:0f:58:87:6b:41:00:00:00:00:9a:c5"
      )
}
