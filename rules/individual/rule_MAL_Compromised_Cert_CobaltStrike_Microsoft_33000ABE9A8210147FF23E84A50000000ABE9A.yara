import "pe"

rule MAL_Compromised_Cert_CobaltStrike_Microsoft_33000ABE9A8210147FF23E84A50000000ABE9A {
   meta:
      description         = "Detects CobaltStrike with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-04"
      version             = "1.0"

      hash                = "53de6d9138476ce0d55fa6a1449d16189478f81f7cd2983580af0e8c8b247a1a"
      malware             = "CobaltStrike"
      malware_type        = "Unknown"
      malware_notes       = "https://rogueauthority.org/signed-loader-cobalt-strike-crowdstrike-disguise"

      signer              = "ISABEL ALEJANDRA FLORES"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:0a:be:9a:82:10:14:7f:f2:3e:84:a5:00:00:00:0a:be:9a"
      cert_thumbprint     = "e9dda859e0566eb29239ad8a92360773e33d087d"
      cert_valid_from     = "2026-11-04"
      cert_valid_to       = "2026-11-07"

      country             = "US"
      state               = "in"
      locality            = "East Chicago"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:0a:be:9a:82:10:14:7f:f2:3e:84:a5:00:00:00:0a:be:9a"
      )
}
