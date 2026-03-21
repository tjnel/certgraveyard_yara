import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_7C74A3C9578969D8A164D63522F4491D {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-08"
      version             = "1.0"

      hash                = "6968840ce1b13d50d13f7f0320a2e5d66bfd97073f325231edc58ec85e694b6b"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Eos Mist LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "7c:74:a3:c9:57:89:69:d8:a1:64:d6:35:22:f4:49:1d"
      cert_thumbprint     = "521676B457B9E2ABB2944222F11AE962C829DDDE"
      cert_valid_from     = "2026-01-08"
      cert_valid_to       = "2027-01-08"

      country             = "IL"
      state               = "Central"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "516234788"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "7c:74:a3:c9:57:89:69:d8:a1:64:d6:35:22:f4:49:1d"
      )
}
