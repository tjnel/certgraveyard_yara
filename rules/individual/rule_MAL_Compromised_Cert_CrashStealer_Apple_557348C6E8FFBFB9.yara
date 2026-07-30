import "pe"

rule MAL_Compromised_Cert_CrashStealer_Apple_557348C6E8FFBFB9 {
   meta:
      description         = "Detects CrashStealer with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "a25b0e2b258aa190009a810380b37cf3324aa538c59b474233197c7cd6f11833"
      malware             = "CrashStealer"
      malware_type        = "Unknown"
      malware_notes       = "https://www.jamf.com/blog/crashstealer-macos-infostealer-analysis/"

      signer              = "Todor Madjarov"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "55:73:48:c6:e8:ff:bf:b9"
      cert_thumbprint     = "42B07B25B6000F14AD74B821B048D8AE9B2E455C"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-02-01"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Apple Inc." and
         sig.serial == "55:73:48:c6:e8:ff:bf:b9"
      )
}
