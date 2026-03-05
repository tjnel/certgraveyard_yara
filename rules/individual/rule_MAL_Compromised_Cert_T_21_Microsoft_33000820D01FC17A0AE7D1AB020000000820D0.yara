import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_33000820D01FC17A0AE7D1AB020000000820D0 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-02"
      version             = "1.0"

      hash                = "b0bb59ffeb08e8aad98ffa76c8c1f409ab6b7a7245099ec41784b15dfcb6630f"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Anquesia Gray"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:20:d0:1f:c1:7a:0a:e7:d1:ab:02:00:00:00:08:20:d0"
      cert_thumbprint     = "F179C7E5E3783EE71AA32CEAA5B844F85427C842"
      cert_valid_from     = "2026-03-02"
      cert_valid_to       = "2026-03-05"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:20:d0:1f:c1:7a:0a:e7:d1:ab:02:00:00:00:08:20:d0"
      )
}
