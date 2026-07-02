import "pe"

rule MAL_Compromised_Cert_HijackLoader_Microsoft_330001385332BA26BC619362AB000000013853 {
   meta:
      description         = "Detects HijackLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-20"
      version             = "1.0"

      hash                = "9c0a88ea53c4e0324157542385a1d342101feb51cf7b8cf76e9441376f1f522a"
      malware             = "HijackLoader"
      malware_type        = "Remote access tool"
      malware_notes       = "This malware uses a fake telegram URL for C2. In this instance, the malware was disguised as a Franz messenger app installer. A previous version was disguised as Telegram."

      signer              = "ELH Palkehituse OÜ"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:38:53:32:ba:26:bc:61:93:62:ab:00:00:00:01:38:53"
      cert_thumbprint     = "725523E6EB27771128C94B14D846277261042A16"
      cert_valid_from     = "2026-05-20"
      cert_valid_to       = "2026-05-23"

      country             = "EE"
      state               = "Põlvamaa"
      locality            = "Valgjärve"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:38:53:32:ba:26:bc:61:93:62:ab:00:00:00:01:38:53"
      )
}
