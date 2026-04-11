import "pe"

rule MAL_Compromised_Cert_FakeNDASign_Microsoft_330008B3D4C50528713453810100000008B3D4 {
   meta:
      description         = "Detects FakeNDASign with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-25"
      version             = "1.0"

      hash                = "80b3c302cb1ab35193d4e54b3df270f5900a96d8848baa23f9505821b7d6610c"
      malware             = "FakeNDASign"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "Robert Walters"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:b3:d4:c5:05:28:71:34:53:81:01:00:00:00:08:b3:d4"
      cert_thumbprint     = "E7A0D1E6DBDEE957127E17E9E40C93A277C9AA09"
      cert_valid_from     = "2026-03-25"
      cert_valid_to       = "2026-03-28"

      country             = "US"
      state               = "California"
      locality            = "Placentia"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:b3:d4:c5:05:28:71:34:53:81:01:00:00:00:08:b3:d4"
      )
}
