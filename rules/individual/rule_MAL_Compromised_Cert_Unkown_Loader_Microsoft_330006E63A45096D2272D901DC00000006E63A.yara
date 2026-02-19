import "pe"

rule MAL_Compromised_Cert_Unkown_Loader_Microsoft_330006E63A45096D2272D901DC00000006E63A {
   meta:
      description         = "Detects Unkown,Loader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-14"
      version             = "1.0"

      hash                = "d532388be87256369b8f61886c45ac13b298d5e3f6853cde361491e9a414381a"
      malware             = "Unkown,Loader"
      malware_type        = "Unknown"
      malware_notes       = "Fake Proton Application"

      signer              = "Anquesia Gray"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:06:e6:3a:45:09:6d:22:72:d9:01:dc:00:00:00:06:e6:3a"
      cert_thumbprint     = "C849B459E8421187078ED13A83B8A17C7B749A23"
      cert_valid_from     = "2026-02-14"
      cert_valid_to       = "2026-02-17"

      country             = "US"
      state               = "Georgia"
      locality            = "Atlanta"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:06:e6:3a:45:09:6d:22:72:d9:01:dc:00:00:00:06:e6:3a"
      )
}
