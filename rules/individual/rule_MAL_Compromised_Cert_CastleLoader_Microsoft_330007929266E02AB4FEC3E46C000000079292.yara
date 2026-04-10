import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330007929266E02AB4FEC3E46C000000079292 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-22"
      version             = "1.0"

      hash                = "9183078ffc982bf226231ac8de4844b06e1daba5a2006b44068dd570d9881020"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: strangury[.]icu"

      signer              = "MIGUEL GUTIERREZLUPERCIO"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:92:92:66:e0:2a:b4:fe:c3:e4:6c:00:00:00:07:92:92"
      cert_thumbprint     = "BD8D5AFDFBBB161EE4777E27583EACDC5ACB475B"
      cert_valid_from     = "2026-03-22"
      cert_valid_to       = "2026-03-25"

      country             = "US"
      state               = "California"
      locality            = "ADELANTO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:92:92:66:e0:2a:b4:fe:c3:e4:6c:00:00:00:07:92:92"
      )
}
