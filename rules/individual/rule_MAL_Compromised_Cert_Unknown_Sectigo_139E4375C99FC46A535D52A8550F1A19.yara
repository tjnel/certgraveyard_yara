import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_139E4375C99FC46A535D52A8550F1A19 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-05"
      version             = "1.0"

      hash                = "23ef632409d12aa644b924ec74687928508e5d17f57c72eca2583e0ec21643cd"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "A2Z Services AB"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "13:9e:43:75:c9:9f:c4:6a:53:5d:52:a8:55:0f:1a:19"
      cert_thumbprint     = "11F3885DC8A43D414CCBE3B5679D9A8B00980C8B"
      cert_valid_from     = "2025-05-05"
      cert_valid_to       = "2026-05-05"

      country             = "SE"
      state               = "Stockholms län"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "559306-4032"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "13:9e:43:75:c9:9f:c4:6a:53:5d:52:a8:55:0f:1a:19"
      )
}
