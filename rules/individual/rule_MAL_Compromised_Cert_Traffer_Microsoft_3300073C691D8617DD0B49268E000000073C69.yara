import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_3300073C691D8617DD0B49268E000000073C69 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-05"
      version             = "1.0"

      hash                = "6a4839a9ab9ea77d36c25955c39b28aa6602fce3489c21a674edf81f9ec2a7f9"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:3c:69:1d:86:17:dd:0b:49:26:8e:00:00:00:07:3c:69"
      cert_thumbprint     = "99B6558FF48DAE39804931051034E90B1951DE48"
      cert_valid_from     = "2026-03-05"
      cert_valid_to       = "2026-03-08"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:3c:69:1d:86:17:dd:0b:49:26:8e:00:00:00:07:3c:69"
      )
}
