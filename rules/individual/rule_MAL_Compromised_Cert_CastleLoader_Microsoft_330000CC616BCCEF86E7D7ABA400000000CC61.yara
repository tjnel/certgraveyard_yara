import "pe"

rule MAL_Compromised_Cert_CastleLoader_Microsoft_330000CC616BCCEF86E7D7ABA400000000CC61 {
   meta:
      description         = "Detects CastleLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-05"
      version             = "1.0"

      hash                = "8ac502f5e918da028a00e72c1e34f8a5ff96449810b1bac0f08bf63d8dc19840"
      malware             = "CastleLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: elvaronexkas[.]com"

      signer              = "Nicky Jaramillo Jr"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:00:cc:61:6b:cc:ef:86:e7:d7:ab:a4:00:00:00:00:cc:61"
      cert_thumbprint     = "03751A7514DD209AA26E9240551F653F9BE484BA"
      cert_valid_from     = "2026-05-05"
      cert_valid_to       = "2026-05-08"

      country             = "US"
      state               = "Washington"
      locality            = "Milton"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:00:cc:61:6b:cc:ef:86:e7:d7:ab:a4:00:00:00:00:cc:61"
      )
}
