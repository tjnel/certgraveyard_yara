import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_3300004F77A8D5C60474AEFDE4000000004F77 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-14"
      version             = "1.0"

      hash                = "4ddda625586db0b45743a86a2825b04ce3a1731f14eea500c52bb1110ae7a594"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex meetings targeting crypto jobseekers worldwide"

      signer              = "KELLY SULLIVAN"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:4f:77:a8:d5:c6:04:74:ae:fd:e4:00:00:00:00:4f:77"
      cert_thumbprint     = "5AE4E7C1EDD41B52F72E4700005BDA7B3159614F"
      cert_valid_from     = "2026-04-14"
      cert_valid_to       = "2026-04-17"

      country             = "US"
      state               = "Alaska"
      locality            = "WASILLA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:4f:77:a8:d5:c6:04:74:ae:fd:e4:00:00:00:00:4f:77"
      )
}
