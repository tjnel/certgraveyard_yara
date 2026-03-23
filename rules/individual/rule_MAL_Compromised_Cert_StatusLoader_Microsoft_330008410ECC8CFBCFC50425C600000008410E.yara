import "pe"

rule MAL_Compromised_Cert_StatusLoader_Microsoft_330008410ECC8CFBCFC50425C600000008410E {
   meta:
      description         = "Detects StatusLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-16"
      version             = "1.0"

      hash                = "a4da16b96abba3e940c2cdfdb6f206b3fad6e0d33134f6f3ec987cbcad9ed83b"
      malware             = "StatusLoader"
      malware_type        = "Unknown"
      malware_notes       = "Malware loader impersonating Rufus"

      signer              = "Elisa Olea"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:41:0e:cc:8c:fb:cf:c5:04:25:c6:00:00:00:08:41:0e"
      cert_thumbprint     = "8FA3A44E1E192F21E048FD7CABCBA764274C8362"
      cert_valid_from     = "2026-03-16"
      cert_valid_to       = "2026-03-19"

      country             = "US"
      state               = "Arizona"
      locality            = "gilbert"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:41:0e:cc:8c:fb:cf:c5:04:25:c6:00:00:00:08:41:0e"
      )
}
