import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330007F670F4216275CF1D6E9300000007F670 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-23"
      version             = "1.0"

      hash                = "e96f42668ed0b9780ae76c2b5af44129d4b63ffbb50e3341bcf724a2c9f9a5f7"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "C2: 198-37-119-78.sslip[.]io"

      signer              = "Julie Jorgensen"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:f6:70:f4:21:62:75:cf:1d:6e:93:00:00:00:07:f6:70"
      cert_thumbprint     = "F0C43DFECF4C53AF1CC5677821E987A27FEB74BF"
      cert_valid_from     = "2026-02-23"
      cert_valid_to       = "2026-02-26"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:f6:70:f4:21:62:75:cf:1d:6e:93:00:00:00:07:f6:70"
      )
}
