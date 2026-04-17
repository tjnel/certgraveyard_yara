import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_33000839C40044B3E475E0C6190000000839C4 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-15"
      version             = "1.0"

      hash                = "82a21a9d92666d3fb6d776e8135ad0e63401f524579e111410eba7f7532f7be0"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Teresa Boswell"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:39:c4:00:44:b3:e4:75:e0:c6:19:00:00:00:08:39:c4"
      cert_thumbprint     = "77A8CA0D224C8294886E1B2056DD03B64134D086"
      cert_valid_from     = "2026-03-15"
      cert_valid_to       = "2026-03-18"

      country             = "US"
      state               = "Arizona"
      locality            = "mesa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:39:c4:00:44:b3:e4:75:e0:c6:19:00:00:00:08:39:c4"
      )
}
