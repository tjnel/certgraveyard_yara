import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300079E8643F87B3C63BDF561000000079E86 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-24"
      version             = "1.0"

      hash                = "82b4cfac54ef2fcfa51c4418aad3acea5577a4e64f6145137576063e9af029c8"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: strangury[.]icu"

      signer              = "MIGUEL GUTIERREZLUPERCIO"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:9e:86:43:f8:7b:3c:63:bd:f5:61:00:00:00:07:9e:86"
      cert_thumbprint     = "4027D4494709EEA7E7F8A226F339D200E47FAA5F"
      cert_valid_from     = "2026-03-24"
      cert_valid_to       = "2026-03-27"

      country             = "US"
      state               = "California"
      locality            = "ADELANTO"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:9e:86:43:f8:7b:3c:63:bd:f5:61:00:00:00:07:9e:86"
      )
}
