import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_3300007141884BAED0CBF91F0D000000007141 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-23"
      version             = "1.0"

      hash                = "471c2173501d6174a0fbaf56580c95e1e2df7ab19995e10ee5bfac1411ee75d9"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "INFOTECK SOLUTIONS PRIVATE LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:71:41:88:4b:ae:d0:cb:f9:1f:0d:00:00:00:00:71:41"
      cert_thumbprint     = "2C769AF041AEC77E20D63BAFB00BB978C3F34642"
      cert_valid_from     = "2026-04-23"
      cert_valid_to       = "2026-04-26"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:71:41:88:4b:ae:d0:cb:f9:1f:0d:00:00:00:00:71:41"
      )
}
