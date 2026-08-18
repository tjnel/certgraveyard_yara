import "pe"

rule MAL_Compromised_Cert_ScreenConnect_Loader_Microsoft_33000023311910DDBBFB8386B2000000002331 {
   meta:
      description         = "Detects ScreenConnect Loader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-09"
      version             = "1.0"

      hash                = "365c52276962b558c0d91d9943205bf79c1d34266f9d1478fa4788aec8f23b37"
      malware             = "ScreenConnect Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Frank Farris"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:23:31:19:10:dd:bb:fb:83:86:b2:00:00:00:00:23:31"
      cert_thumbprint     = "f6cba45b562ba250e47cf7fca4a04e807cd3d80b"
      cert_valid_from     = "2026-04-09"
      cert_valid_to       = "2026-04-12"

      country             = "US"
      state               = "Tennessee"
      locality            = "nashville"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:23:31:19:10:dd:bb:fb:83:86:b2:00:00:00:00:23:31"
      )
}
