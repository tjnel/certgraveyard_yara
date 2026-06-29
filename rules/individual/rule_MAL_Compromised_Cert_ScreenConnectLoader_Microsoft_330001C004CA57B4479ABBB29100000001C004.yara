import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001C004CA57B4479ABBB29100000001C004 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-06"
      version             = "1.0"

      hash                = "c575b70364b545cbe06b1f7aabb5a05055cc58a0851b102a98339783e7037b89"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Danielle Hale"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:c0:04:ca:57:b4:47:9a:bb:b2:91:00:00:00:01:c0:04"
      cert_thumbprint     = "8B3ED776A602699778BE8DBEA44A14DD90C26A65"
      cert_valid_from     = "2026-06-06"
      cert_valid_to       = "2026-06-09"

      country             = "US"
      state               = "oh"
      locality            = "Cleveland"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:c0:04:ca:57:b4:47:9a:bb:b2:91:00:00:00:01:c0:04"
      )
}
