import "pe"

rule MAL_Compromised_Cert_ScreenConnect_Phishing_Microsoft_33000134CBF38FAAA2C101914E0000000134CB {
   meta:
      description         = "Detects ScreenConnect Phishing with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-20"
      version             = "1.0"

      hash                = "e957dd4a5dcdef4dbee5c9a2d4e7a421805e0a9019b615308e5e393d607da8d1"
      malware             = "ScreenConnect Phishing"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Chaunesey Morrison"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:01:34:cb:f3:8f:aa:a2:c1:01:91:4e:00:00:00:01:34:cb"
      cert_thumbprint     = "664010A73455F1920D382DD418DAADB7753FCEEC"
      cert_valid_from     = "2026-05-20"
      cert_valid_to       = "2026-05-23"

      country             = "US"
      state               = "Texas"
      locality            = "converse"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:01:34:cb:f3:8f:aa:a2:c1:01:91:4e:00:00:00:01:34:cb"
      )
}
