import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001AA4D046B2F3152C2188E00000001AA4D {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-04"
      version             = "1.0"

      hash                = "5700715b1f7cc10e3a6ec3836d88067637a7055f36260d1e1c91d4db65eb4dbd"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Paula Foster"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:aa:4d:04:6b:2f:31:52:c2:18:8e:00:00:00:01:aa:4d"
      cert_thumbprint     = "2B0CC64FFC6214F01B17C01DABA0997D7B1F8C98"
      cert_valid_from     = "2026-06-04"
      cert_valid_to       = "2026-06-07"

      country             = "US"
      state               = "fl"
      locality            = "Saint James City"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:aa:4d:04:6b:2f:31:52:c2:18:8e:00:00:00:01:aa:4d"
      )
}
