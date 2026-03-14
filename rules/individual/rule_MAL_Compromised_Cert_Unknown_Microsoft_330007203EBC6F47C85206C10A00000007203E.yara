import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330007203EBC6F47C85206C10A00000007203E {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-27"
      version             = "1.0"

      hash                = "ceffb43a1accb587a4d7dcff57320c74d60cdd7c73cdc287518fe2e269390258"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "Trojanized game installers. Detonation -> https://app.any.run/tasks/b573136d-3902-4c14-91b6-e38def28e96f"

      signer              = "Ricardo Reis"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:20:3e:bc:6f:47:c8:52:06:c1:0a:00:00:00:07:20:3e"
      cert_thumbprint     = "D7ED9F040EBAEE5B1ADF83E40D2F9D234E42DB47"
      cert_valid_from     = "2026-02-27"
      cert_valid_to       = "2026-03-02"

      country             = "US"
      state               = "South Carolina"
      locality            = "Johnston"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:20:3e:bc:6f:47:c8:52:06:c1:0a:00:00:00:07:20:3e"
      )
}
