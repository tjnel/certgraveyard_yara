import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300001CF70654DAD728BA5763000000001CF7 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-15"
      version             = "1.0"

      hash                = "6904ca08e4d7d398db3d54ae22e1f211219499f17f1090d407850a6f8304e47f"
      malware             = "ScreenConnectLoader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Blanchard Nivell"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:1c:f7:06:54:da:d7:28:ba:57:63:00:00:00:00:1c:f7"
      cert_thumbprint     = "C2974FF5D64D077C32FF01A3868B61792C0DB84C"
      cert_valid_from     = "2026-04-15"
      cert_valid_to       = "2026-04-18"

      country             = "US"
      state               = "Texas"
      locality            = "SAN ANTONIO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:1c:f7:06:54:da:d7:28:ba:57:63:00:00:00:00:1c:f7"
      )
}
