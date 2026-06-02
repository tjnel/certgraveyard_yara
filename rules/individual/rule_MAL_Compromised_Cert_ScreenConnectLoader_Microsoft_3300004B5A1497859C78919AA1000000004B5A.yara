import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300004B5A1497859C78919AA1000000004B5A {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-19"
      version             = "1.0"

      hash                = "cced80f9cfb2b9f67658d50fa4e45312ca2ed620bb981481177e434ee9acb984"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Avery Benavidez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:4b:5a:14:97:85:9c:78:91:9a:a1:00:00:00:00:4b:5a"
      cert_thumbprint     = "88660C18B3BEA8277A0F00F385792734880D733D"
      cert_valid_from     = "2026-04-19"
      cert_valid_to       = "2026-04-22"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:4b:5a:14:97:85:9c:78:91:9a:a1:00:00:00:00:4b:5a"
      )
}
