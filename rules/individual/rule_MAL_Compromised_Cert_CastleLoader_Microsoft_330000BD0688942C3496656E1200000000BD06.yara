import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330000BD0688942C3496656E1200000000BD06 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-04"
      version             = "1.0"

      hash                = "a8bd56accd95b9d33c9b2e32d1349c8d5b89246838b3fa86697c160606dfbfd2"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Soft Insanity Oy"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:bd:06:88:94:2c:34:96:65:6e:12:00:00:00:00:bd:06"
      cert_thumbprint     = "2B0E49CE19D7186A335A6D4D07B5606C184FAA16"
      cert_valid_from     = "2026-05-04"
      cert_valid_to       = "2026-05-07"

      country             = "FI"
      state               = "Central Finland"
      locality            = "Hämeenlinna"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:bd:06:88:94:2c:34:96:65:6e:12:00:00:00:00:bd:06"
      )
}
