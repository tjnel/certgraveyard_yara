import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_33000729ED2E7CC5AB0849D7E90000000729ED {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-01"
      version             = "1.0"

      hash                = "f00122674105b522a219cae0728cdfe14c1ef9fd43ccf4df6f15b7fc2e1772fe"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Anquesia Gray"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:29:ed:2e:7c:c5:ab:08:49:d7:e9:00:00:00:07:29:ed"
      cert_thumbprint     = "5F89B706B099ECA3F76EE51B3C9BE4B97D2328D6"
      cert_valid_from     = "2026-03-01"
      cert_valid_to       = "2026-03-04"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:29:ed:2e:7c:c5:ab:08:49:d7:e9:00:00:00:07:29:ed"
      )
}
