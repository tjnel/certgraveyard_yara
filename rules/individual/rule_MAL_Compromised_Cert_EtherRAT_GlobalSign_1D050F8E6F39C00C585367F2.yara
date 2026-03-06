import "pe"

rule MAL_Compromised_Cert_EtherRAT_GlobalSign_1D050F8E6F39C00C585367F2 {
   meta:
      description         = "Detects EtherRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-08-19"
      version             = "1.0"

      hash                = "61882e8813e03a91adb06a282118ac522d7f8490a9995a57ca37bb71abc2a716"
      malware             = "EtherRAT"
      malware_type        = "Unknown"
      malware_notes       = "C2: franksinatra[.]icu"

      signer              = "LLC Innovative Technologies"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1d:05:0f:8e:6f:39:c0:0c:58:53:67:f2"
      cert_thumbprint     = "B37328421770C6C7A48D58457EEE283B5E712EC4"
      cert_valid_from     = "2025-08-19"
      cert_valid_to       = "2026-07-12"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1d:05:0f:8e:6f:39:c0:0c:58:53:67:f2"
      )
}
