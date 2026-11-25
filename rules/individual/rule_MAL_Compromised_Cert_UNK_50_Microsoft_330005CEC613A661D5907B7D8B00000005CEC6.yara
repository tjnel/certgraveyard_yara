import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330005CEC613A661D5907B7D8B00000005CEC6 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-02"
      version             = "1.0"

      hash                = "ea4ac6017a5a5c1520afbd48465d2127be51917fafec9f3850102db614cbace2"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Technoservice B.V."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:05:ce:c6:13:a6:61:d5:90:7b:7d:8b:00:00:00:05:ce:c6"
      cert_thumbprint     = "f077b3a63673679ee0de886b631f3996c76d9579"
      cert_valid_from     = "2026-09-02"
      cert_valid_to       = "2026-09-05"

      country             = "NL"
      state               = "Zuid-Holland"
      locality            = "Hellevoetsluis"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:05:ce:c6:13:a6:61:d5:90:7b:7d:8b:00:00:00:05:ce:c6"
      )
}
