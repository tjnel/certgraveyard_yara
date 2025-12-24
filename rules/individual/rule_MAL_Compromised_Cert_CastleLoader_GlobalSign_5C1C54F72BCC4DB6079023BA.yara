import "pe"

rule MAL_Compromised_Cert_CastleLoader_GlobalSign_5C1C54F72BCC4DB6079023BA {
   meta:
      description         = "Detects CastleLoader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-20"
      version             = "1.0"

      hash                = "7ce399ae92c3e79a25e9013b2c81fe0add119bda0a65336d1e5c231654db01a5"
      malware             = "CastleLoader"
      malware_type        = "Initial access tool"
      malware_notes       = "This copy was a trojanized Advanced IP scanner installer."

      signer              = "NOMAC LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5c:1c:54:f7:2b:cc:4d:b6:07:90:23:ba"
      cert_thumbprint     = "2C28CC8AFC87E5B059623D8F655DFAA5D1E0274B"
      cert_valid_from     = "2025-08-20"
      cert_valid_to       = "2026-05-20"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1257700190373"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5c:1c:54:f7:2b:cc:4d:b6:07:90:23:ba"
      )
}
