import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300070C3A5C15733DA5CD40AB000000070C3A {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-22"
      version             = "1.0"

      hash                = "0b98f3b8281e7234a3243ea7cf85340ba20107bd103574547e97a8623eddbd04"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marni Hirschorn"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:0c:3a:5c:15:73:3d:a5:cd:40:ab:00:00:00:07:0c:3a"
      cert_thumbprint     = "7A2FB342C3319774657C37A8B76E591630F94797"
      cert_valid_from     = "2026-02-22"
      cert_valid_to       = "2026-02-25"

      country             = "US"
      state               = "New Jersey"
      locality            = "Woodcliff Lake"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:0c:3a:5c:15:73:3d:a5:cd:40:ab:00:00:00:07:0c:3a"
      )
}
