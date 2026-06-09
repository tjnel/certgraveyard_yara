import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Microsoft_330000EBF2267F501774231D3600000000EBF2 {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-09"
      version             = "1.0"

      hash                = "2fe7b6aeeea82a71d754d61bd2e0edf592248d01e0f81c7bd3e7b1a5be1da2ab"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "A&A Interactive Media Group"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:eb:f2:26:7f:50:17:74:23:1d:36:00:00:00:00:eb:f2"
      cert_thumbprint     = "98C2DFD4E2533D1492CE12E279509F8865B304E0"
      cert_valid_from     = "2026-05-09"
      cert_valid_to       = "2026-05-12"

      country             = "NL"
      state               = "Noord-Brabant"
      locality            = "Helmond"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:eb:f2:26:7f:50:17:74:23:1d:36:00:00:00:00:eb:f2"
      )
}
