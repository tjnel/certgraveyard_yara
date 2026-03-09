import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330007D55E53DD8514C78F28B500000007D55E {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-26"
      version             = "1.0"

      hash                = "9cf66f291d3a7f42ddd7393d8fbd95fc12e223b12fbdd31c52d8c46b3decb444"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "Trojanized game installers. Detonation -> https://app.any.run/tasks/b573136d-3902-4c14-91b6-e38def28e96f"

      signer              = "Ricardo Reis"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:07:d5:5e:53:dd:85:14:c7:8f:28:b5:00:00:00:07:d5:5e"
      cert_thumbprint     = "8E94AE3C62C33BE5F19002D21CC658ABD866D12A"
      cert_valid_from     = "2026-02-26"
      cert_valid_to       = "2026-03-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:07:d5:5e:53:dd:85:14:c7:8f:28:b5:00:00:00:07:d5:5e"
      )
}
