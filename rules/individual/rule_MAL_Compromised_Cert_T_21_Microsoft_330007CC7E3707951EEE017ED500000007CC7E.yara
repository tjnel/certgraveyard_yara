import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330007CC7E3707951EEE017ED500000007CC7E {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-16"
      version             = "1.0"

      hash                = "1325a627124c5372e5825fa7329c76ea0f421ea96574fc42e7ea18c783692ab7"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = "Fake Webex builds delivered from fake meeting websites impersonating companies worldwide"

      signer              = "Anquesia Gray"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:cc:7e:37:07:95:1e:ee:01:7e:d5:00:00:00:07:cc:7e"
      cert_thumbprint     = "C1A17F2290B1C7A56E54424D7F1022E8ED30D456"
      cert_valid_from     = "2026-02-16"
      cert_valid_to       = "2026-02-19"

      country             = "US"
      state               = "Georgia"
      locality            = "Atlanta"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:cc:7e:37:07:95:1e:ee:01:7e:d5:00:00:00:07:cc:7e"
      )
}
