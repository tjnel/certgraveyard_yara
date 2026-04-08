import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330007C55BD31142C199294EA500000007C55B {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-01"
      version             = "1.0"

      hash                = "6ebd717e08ccc4ebb89e22240ceec829266d3a2ea7ecfc4a0af11415dc7af302"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "WILLIAM LAWLER"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:c5:5b:d3:11:42:c1:99:29:4e:a5:00:00:00:07:c5:5b"
      cert_thumbprint     = "DD9E0441A5BE957FE5BDCA0BC2368C94B2A0F705"
      cert_valid_from     = "2026-04-01"
      cert_valid_to       = "2026-04-04"

      country             = "US"
      state               = "California"
      locality            = "ACTON"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:c5:5b:d3:11:42:c1:99:29:4e:a5:00:00:00:07:c5:5b"
      )
}
