import "pe"

rule MAL_Compromised_Cert_StatusLoader_Microsoft_33000782978A81DFD059A5E20A000000078297 {
   meta:
      description         = "Detects StatusLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-20"
      version             = "1.0"

      hash                = "8a2347f18be7cbf3524645269052d726e753d311f73f16369cedcc5966db3c67"
      malware             = "StatusLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MATTHEW PIGG"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:82:97:8a:81:df:d0:59:a5:e2:0a:00:00:00:07:82:97"
      cert_thumbprint     = "B7ABE141BA1A5460872295447502DD9A9C3CBD63"
      cert_valid_from     = "2026-03-20"
      cert_valid_to       = "2026-03-23"

      country             = "US"
      state               = "California"
      locality            = "RICHMOND"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:82:97:8a:81:df:d0:59:a5:e2:0a:00:00:00:07:82:97"
      )
}
