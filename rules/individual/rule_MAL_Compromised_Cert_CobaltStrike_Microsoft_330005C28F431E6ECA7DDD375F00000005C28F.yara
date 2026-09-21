import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Microsoft_330005C28F431E6ECA7DDD375F00000005C28F {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-01"
      version             = "1.0"

      hash                = "37dc4b90367a8a655b0337d561ab6e1ca97c0d1b1b9598c08288d940e380780e"
      malware             = "CobaltStrike"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alysen Mendez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:05:c2:8f:43:1e:6e:ca:7d:dd:37:5f:00:00:00:05:c2:8f"
      cert_thumbprint     = "917eb32056350952015533f340398c4771e69247"
      cert_valid_from     = "2026-09-01"
      cert_valid_to       = "2026-09-04"

      country             = "US"
      state               = "New Jersey"
      locality            = "LITTLE FERRY"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:05:c2:8f:43:1e:6e:ca:7d:dd:37:5f:00:00:00:05:c2:8f"
      )
}
