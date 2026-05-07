import "pe"

rule MAL_Compromised_Cert_APXLoader_Microsoft_33000062B8AAEAC98C2824DD500000000062B8 {
   meta:
      description         = "Detects APXLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-21"
      version             = "1.0"

      hash                = "2452052f577dac4719bde7e02cbfd69aa0d3bebf21a14ccb93c0cd6e7ac1c94c"
      malware             = "APXLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "SOPHIA MONGILLO"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:62:b8:aa:ea:c9:8c:28:24:dd:50:00:00:00:00:62:b8"
      cert_thumbprint     = "0E6AB06DB5363F5194EE867E5F8A66C9B0FF973C"
      cert_valid_from     = "2026-04-21"
      cert_valid_to       = "2026-04-24"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:62:b8:aa:ea:c9:8c:28:24:dd:50:00:00:00:00:62:b8"
      )
}
