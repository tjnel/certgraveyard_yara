import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330008224666C9E529903DB5AF000000082246 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-02"
      version             = "1.0"

      hash                = "6e09ccbc3001f784b23b9e4c216bc68f3c3df16e0140cee7fa4f9857d34f7203"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JAMIE QUIGGINS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:22:46:66:c9:e5:29:90:3d:b5:af:00:00:00:08:22:46"
      cert_thumbprint     = "F6D38B2CB32DAA0D0DB4AAB7FC3E8EBD947FE384"
      cert_valid_from     = "2026-03-02"
      cert_valid_to       = "2026-03-05"

      country             = "US"
      state               = "California"
      locality            = "Los Angeles"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:22:46:66:c9:e5:29:90:3d:b5:af:00:00:00:08:22:46"
      )
}
