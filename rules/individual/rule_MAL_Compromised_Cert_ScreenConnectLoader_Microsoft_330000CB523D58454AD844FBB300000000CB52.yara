import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000CB523D58454AD844FBB300000000CB52 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-07"
      version             = "1.0"

      hash                = "c5579ebb5ccf8b3de0be128ac56384dc5a2ca26cafa5cb389ef7b234537578b7"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Morrison Chaunesey"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:cb:52:3d:58:45:4a:d8:44:fb:b3:00:00:00:00:cb:52"
      cert_thumbprint     = "C1AF406AC082B9C65EAAF212D77F15FDBCA4340A"
      cert_valid_from     = "2026-05-07"
      cert_valid_to       = "2026-05-10"

      country             = "US"
      state               = "Texas"
      locality            = "Converse"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:cb:52:3d:58:45:4a:d8:44:fb:b3:00:00:00:00:cb:52"
      )
}
