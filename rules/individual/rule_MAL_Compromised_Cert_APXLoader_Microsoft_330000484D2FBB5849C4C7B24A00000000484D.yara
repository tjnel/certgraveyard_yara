import "pe"

rule MAL_Compromised_Cert_APXLoader_Microsoft_330000484D2FBB5849C4C7B24A00000000484D {
   meta:
      description         = "Detects APXLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-13"
      version             = "1.0"

      hash                = "61aca585687ec21a182342a40de3eaa12d3fc0d92577456cae0df37c3ed28e99"
      malware             = "APXLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "Vic Thadhani"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:48:4d:2f:bb:58:49:c4:c7:b2:4a:00:00:00:00:48:4d"
      cert_thumbprint     = "80DB2376BBDC456B28A48CF2C0D4B29871A7EF9D"
      cert_valid_from     = "2026-04-13"
      cert_valid_to       = "2026-04-16"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:48:4d:2f:bb:58:49:c4:c7:b2:4a:00:00:00:00:48:4d"
      )
}
