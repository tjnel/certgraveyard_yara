import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_33000771609E6AB5C9E594E776000000077160 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-16"
      version             = "1.0"

      hash                = "a74cbcfdadc1bcef61373536e4139d8221e6d3da57a3dd8960113263c57c97ee"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:71:60:9e:6a:b5:c9:e5:94:e7:76:00:00:00:07:71:60"
      cert_thumbprint     = "360D80385925F2D0BD5039EFCCF1AB0DB3B3D690"
      cert_valid_from     = "2026-03-16"
      cert_valid_to       = "2026-03-19"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:71:60:9e:6a:b5:c9:e5:94:e7:76:00:00:00:07:71:60"
      )
}
