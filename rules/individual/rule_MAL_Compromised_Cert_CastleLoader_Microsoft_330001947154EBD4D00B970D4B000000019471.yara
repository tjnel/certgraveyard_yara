import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330001947154EBD4D00B970D4B000000019471 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-01"
      version             = "1.0"

      hash                = "c25c07c6fecdd5bafece9c3cfd66dd1749fa5af95775a8956d7d68f844cd011f"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Elusive Techno"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:94:71:54:eb:d4:d0:0b:97:0d:4b:00:00:00:01:94:71"
      cert_thumbprint     = "34196200DC173B2EFE187A3EF124267198837F91"
      cert_valid_from     = "2026-06-01"
      cert_valid_to       = "2026-06-04"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:94:71:54:eb:d4:d0:0b:97:0d:4b:00:00:00:01:94:71"
      )
}
