import "pe"

rule MAL_Compromised_Cert_Unknown_Fake_Browser_update_GlobalSign_733CFAED784964232D1A8EFE {
   meta:
      description         = "Detects Unknown, Fake Browser update with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-22"
      version             = "1.0"

      hash                = "66c6145976275f9dafd40e291d3c4ee9446a11dbf93aebba6097068ed922ffc7"
      malware             = "Unknown, Fake Browser update"
      malware_type        = "Browser Hijacker"
      malware_notes       = "App loads Edge Bitcoin Wallet components to intercept credit card and crypto wallet information."

      signer              = "Weifang Jinqihua Human Resources Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "73:3c:fa:ed:78:49:64:23:2d:1a:8e:fe"
      cert_thumbprint     = "30EB1176D171BD54C3E69CCF0F61288BB0667991"
      cert_valid_from     = "2025-04-22"
      cert_valid_to       = "2026-04-23"

      country             = "CN"
      state               = "Shandong"
      locality            = "Weifang"
      email               = "???"
      rdn_serial_number   = "91370705MA3U9MRD7T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "73:3c:fa:ed:78:49:64:23:2d:1a:8e:fe"
      )
}
