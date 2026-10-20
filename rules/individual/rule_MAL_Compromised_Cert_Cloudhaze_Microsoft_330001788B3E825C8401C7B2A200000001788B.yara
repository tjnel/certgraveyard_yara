import "pe"

rule MAL_Compromised_Cert_Cloudhaze_Microsoft_330001788B3E825C8401C7B2A200000001788B {
   meta:
      description         = "Detects Cloudhaze with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-27"
      version             = "1.0"

      hash                = "5340ac0e58ad432c252c4cbbe486a534dd10013b3bf202adc49c418a0727784b"
      malware             = "Cloudhaze"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PULSE TECH INC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:78:8b:3e:82:5c:84:01:c7:b2:a2:00:00:00:01:78:8b"
      cert_thumbprint     = "c9951db9e38e47a5933f158b4d0f21ed8f6a2101"
      cert_valid_from     = "2026-05-27"
      cert_valid_to       = "2026-05-30"

      country             = "US"
      state               = "California"
      locality            = "West Hollywood"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:78:8b:3e:82:5c:84:01:c7:b2:a2:00:00:00:01:78:8b"
      )
}
