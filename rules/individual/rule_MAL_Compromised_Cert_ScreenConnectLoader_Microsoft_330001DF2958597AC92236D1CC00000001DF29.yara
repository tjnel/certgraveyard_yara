import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001DF2958597AC92236D1CC00000001DF29 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-08"
      version             = "1.0"

      hash                = "0de52ded69fa103440a3dfcb11f3abcdde227037057d86c7f6fe5750cb0b3993"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:df:29:58:59:7a:c9:22:36:d1:cc:00:00:00:01:df:29"
      cert_thumbprint     = "2967DFB3E49066FA08BB9A6F51674D73E6748028"
      cert_valid_from     = "2026-06-08"
      cert_valid_to       = "2026-06-11"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:df:29:58:59:7a:c9:22:36:d1:cc:00:00:00:01:df:29"
      )
}
