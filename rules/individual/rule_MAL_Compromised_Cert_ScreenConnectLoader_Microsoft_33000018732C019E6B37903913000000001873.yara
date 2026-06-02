import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_33000018732C019E6B37903913000000001873 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "9fe60d0ab8215cda561798f4ce4e502d4fca8c68eaca31dded3c2b66fa8e5fc5"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:18:73:2c:01:9e:6b:37:90:39:13:00:00:00:00:18:73"
      cert_thumbprint     = "4683710F0B5647D9C1D6DFAE15D6909448246BD1"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2026-04-11"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:18:73:2c:01:9e:6b:37:90:39:13:00:00:00:00:18:73"
      )
}
