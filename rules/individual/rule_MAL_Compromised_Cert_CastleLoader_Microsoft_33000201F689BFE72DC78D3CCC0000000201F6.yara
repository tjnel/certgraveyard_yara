import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_33000201F689BFE72DC78D3CCC0000000201F6 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-16"
      version             = "1.0"

      hash                = "b0a6f7afa4877eab5085d49207e26d1d2461d2d61d71a4d406e81e9f30711c5e"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:02:01:f6:89:bf:e7:2d:c7:8d:3c:cc:00:00:00:02:01:f6"
      cert_thumbprint     = "D3737D02C7F150D7C4D5139C0251FAC31D6F08A4"
      cert_valid_from     = "2026-06-16"
      cert_valid_to       = "2026-06-19"

      country             = "DK"
      state               = "Central Jutland"
      locality            = "Hammel"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:02:01:f6:89:bf:e7:2d:c7:8d:3c:cc:00:00:00:02:01:f6"
      )
}
