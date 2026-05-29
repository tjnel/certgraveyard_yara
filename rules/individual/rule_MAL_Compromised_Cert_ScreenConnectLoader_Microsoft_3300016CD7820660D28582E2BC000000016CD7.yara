import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300016CD7820660D28582E2BC000000016CD7 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-26"
      version             = "1.0"

      hash                = "7c972f72a7493d8e879e95ed126bab16851ba43cbb25c7e007f5d039ac992cb4"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sabrina Perry"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:6c:d7:82:06:60:d2:85:82:e2:bc:00:00:00:01:6c:d7"
      cert_thumbprint     = "E875C22E3FE2FE156DA8E28B6336B29040CBC982"
      cert_valid_from     = "2026-05-26"
      cert_valid_to       = "2026-05-29"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:6c:d7:82:06:60:d2:85:82:e2:bc:00:00:00:01:6c:d7"
      )
}
