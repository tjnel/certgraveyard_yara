import "pe"

rule MAL_Compromised_Cert_LoremIpsumLoader_Microsoft_330007C066AA4007786CB243E900000007C066 {
   meta:
      description         = "Detects LoremIpsumLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-31"
      version             = "1.0"

      hash                = "0cc2afb8a1fa09db1502441113d5e3d1eac1c7fce2270bd27a7fd55c78bcd6ce"
      malware             = "LoremIpsumLoader"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "Stalin Romero"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:c0:66:aa:40:07:78:6c:b2:43:e9:00:00:00:07:c0:66"
      cert_thumbprint     = "3250A2C506874F74BF7CE256243E7E7D80ADD752"
      cert_valid_from     = "2026-03-31"
      cert_valid_to       = "2026-04-03"

      country             = "US"
      state               = "Texas"
      locality            = "Richmond"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:c0:66:aa:40:07:78:6c:b2:43:e9:00:00:00:07:c0:66"
      )
}
