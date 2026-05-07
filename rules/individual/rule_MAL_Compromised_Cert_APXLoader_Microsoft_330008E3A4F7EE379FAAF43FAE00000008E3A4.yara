import "pe"

rule MAL_Compromised_Cert_APXLoader_Microsoft_330008E3A4F7EE379FAAF43FAE00000008E3A4 {
   meta:
      description         = "Detects APXLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "82aa6df2aa34091240de8dbb98d2e16bbf71b340a6d2e93cc97ce1fd3838e192"
      malware             = "APXLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "Vic Thadhani"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:e3:a4:f7:ee:37:9f:aa:f4:3f:ae:00:00:00:08:e3:a4"
      cert_thumbprint     = "582FB85A07481819B757C374FB7E9995F761705B"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2026-04-04"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:e3:a4:f7:ee:37:9f:aa:f4:3f:ae:00:00:00:08:e3:a4"
      )
}
