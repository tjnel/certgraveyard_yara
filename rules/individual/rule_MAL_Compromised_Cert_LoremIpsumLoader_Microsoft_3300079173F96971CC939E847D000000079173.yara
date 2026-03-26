import "pe"

rule MAL_Compromised_Cert_LoremIpsumLoader_Microsoft_3300079173F96971CC939E847D000000079173 {
   meta:
      description         = "Detects LoremIpsumLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-22"
      version             = "1.0"

      hash                = "6252b766f320ac628c8b399c3939ef0783c7f214758cfc8b429d799a1f34c34a"
      malware             = "LoremIpsumLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Eliezer Valentin"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:91:73:f9:69:71:cc:93:9e:84:7d:00:00:00:07:91:73"
      cert_thumbprint     = "1E488E22A8A99FADFAC690175833F972738A9262"
      cert_valid_from     = "2026-03-22"
      cert_valid_to       = "2026-03-25"

      country             = "US"
      state               = "Texas"
      locality            = "CEDAR HILL"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:91:73:f9:69:71:cc:93:9e:84:7d:00:00:00:07:91:73"
      )
}
