import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330008662D5D7BE110387308A000000008662D {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-22"
      version             = "1.0"

      hash                = "4834845a41a26479e00660c0e2ca85d751e7be0162aca908b75d8ac59e4a5125"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "GUERRERO DEBRA"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:66:2d:5d:7b:e1:10:38:73:08:a0:00:00:00:08:66:2d"
      cert_thumbprint     = "A20F695C01A7017703E07373D48D821F9C648AE1"
      cert_valid_from     = "2026-03-22"
      cert_valid_to       = "2026-03-25"

      country             = "US"
      state               = "Texas"
      locality            = "SAN ANTONIO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:66:2d:5d:7b:e1:10:38:73:08:a0:00:00:00:08:66:2d"
      )
}
