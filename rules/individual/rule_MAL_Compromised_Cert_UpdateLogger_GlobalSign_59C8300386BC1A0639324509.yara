import "pe"

rule MAL_Compromised_Cert_UpdateLogger_GlobalSign_59C8300386BC1A0639324509 {
   meta:
      description         = "Detects UpdateLogger with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-21"
      version             = "1.0"

      hash                = "bbd3e7ff557eaebed512478546726b819a33748958d4536cfc9708385dd07fbb"
      malware             = "UpdateLogger"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Bodensee Privatradio Gesellschaft m.b.H."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "59:c8:30:03:86:bc:1a:06:39:32:45:09"
      cert_thumbprint     = "58dba00baeb33615dad5f269a062abcd13eee73a"
      cert_valid_from     = "2026-04-21"
      cert_valid_to       = "2027-04-22"

      country             = "AT"
      state               = "Vorarlberg"
      locality            = "Schwarzach"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "59:c8:30:03:86:bc:1a:06:39:32:45:09"
      )
}
