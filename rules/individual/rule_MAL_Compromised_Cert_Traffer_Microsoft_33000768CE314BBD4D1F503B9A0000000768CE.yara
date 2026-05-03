import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_33000768CE314BBD4D1F503B9A0000000768CE {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-12"
      version             = "1.0"

      hash                = "106803719e4aaf7439378baa6a6400d7b40ea0e71fa0f0d5199a7037a6e1a470"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:68:ce:31:4b:bd:4d:1f:50:3b:9a:00:00:00:07:68:ce"
      cert_thumbprint     = "E42BB5C169FAA21020172E954BC875A8644155D8"
      cert_valid_from     = "2026-03-12"
      cert_valid_to       = "2026-03-15"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:68:ce:31:4b:bd:4d:1f:50:3b:9a:00:00:00:07:68:ce"
      )
}
