import "pe"

rule MAL_Compromised_Cert_CrashStealer_Apple_757524A42FCCB2F3 {
   meta:
      description         = "Detects CrashStealer with compromised cert (Apple)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-14"
      version             = "1.0"

      hash                = "3c2227bf19e1c955aa405ea712263567aa4b8398a04d299c0f1ac72a68d8b078"
      malware             = "CrashStealer"
      malware_type        = "Unknown"
      malware_notes       = "https://www.jamf.com/blog/crashstealer-macos-infostealer-analysis/"

      signer              = "Todor Madjarov"
      cert_issuer_short   = "Apple"
      cert_issuer         = "Apple Inc."
      cert_serial         = "75:75:24:a4:2f:cc:b2:f3"
      cert_thumbprint     = "769483756F573FC3471D89CCCC395DEB077D701F"
      cert_valid_from     = "2026-07-14"
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
         sig.serial == "75:75:24:a4:2f:cc:b2:f3"
      )
}
