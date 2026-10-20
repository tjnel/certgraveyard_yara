import "pe"

rule MAL_Compromised_Cert_Cloudhaze_Microsoft_330007EAF871AF62C43CBE0CA000000007EAF8 {
   meta:
      description         = "Detects Cloudhaze with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-08"
      version             = "1.0"

      hash                = "e1188168c68818a911d29ff57283a2850e8aad3dc25346426eb169d0a8c2911f"
      malware             = "Cloudhaze"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "PULSE TECH INC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:07:ea:f8:71:af:62:c4:3c:be:0c:a0:00:00:00:07:ea:f8"
      cert_thumbprint     = "5960b7f4c92af6832021a9ee81a297abfcddf7e3"
      cert_valid_from     = "2026-10-08"
      cert_valid_to       = "2026-10-11"

      country             = "US"
      state               = "California"
      locality            = "West Hollywood"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:07:ea:f8:71:af:62:c4:3c:be:0c:a0:00:00:00:07:ea:f8"
      )
}
