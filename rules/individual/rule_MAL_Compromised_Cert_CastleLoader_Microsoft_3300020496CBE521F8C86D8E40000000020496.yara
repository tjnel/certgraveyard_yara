import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300020496CBE521F8C86D8E40000000020496 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-12"
      version             = "1.0"

      hash                = "8389bce4500a67cd5925de17c94e053eba4fd527e30d001a045c3442f055c3b3"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: lumetaro[.]com"

      signer              = "Table for Len"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:02:04:96:cb:e5:21:f8:c8:6d:8e:40:00:00:00:02:04:96"
      cert_thumbprint     = "01ABCA09628346772F90B9F4A67E5C3689147A17"
      cert_valid_from     = "2026-06-12"
      cert_valid_to       = "2026-06-15"

      country             = "NL"
      state               = "Noord-Holland"
      locality            = "Amsterdam"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:02:04:96:cb:e5:21:f8:c8:6d:8e:40:00:00:00:02:04:96"
      )
}
