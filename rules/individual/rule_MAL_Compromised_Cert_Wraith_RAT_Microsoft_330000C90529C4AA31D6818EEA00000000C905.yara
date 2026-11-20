import "pe"

rule MAL_Compromised_Cert_Wraith_RAT_Microsoft_330000C90529C4AA31D6818EEA00000000C905 {
   meta:
      description         = "Detects Wraith RAT with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-05"
      version             = "1.0"

      hash                = "9911a3452701797899b1ea65a6f1c85ad34f7f672abc3f0e43f87dae9e74ce82"
      malware             = "Wraith RAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Rha Soft Limited"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:c9:05:29:c4:aa:31:d6:81:8e:ea:00:00:00:00:c9:05"
      cert_thumbprint     = "52b5a4dbe2684e22c4a331832138563b216e49f8"
      cert_valid_from     = "2026-05-05"
      cert_valid_to       = "2026-05-08"

      country             = "GB"
      state               = "Bedford"
      locality            = "Luton"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:c9:05:29:c4:aa:31:d6:81:8e:ea:00:00:00:00:c9:05"
      )
}
