import "pe"

rule MAL_Compromised_Cert_Unknown_Fake_Browser_update_GlobalSign_79A789837A15BAF721307D48 {
   meta:
      description         = "Detects Unknown, Fake Browser update with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-05-15"
      version             = "1.0"

      hash                = "1c56cdf0748404c03642466ce9223cc3084f0bc25365fde7a8f1c4e47b01bc9d"
      malware             = "Unknown, Fake Browser update"
      malware_type        = "Unknown"
      malware_notes       = "App loads Edge Bitcoin Wallet components to intercept credit card and crypto wallet information."

      signer              = "LISTERA LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "79:a7:89:83:7a:15:ba:f7:21:30:7d:48"
      cert_thumbprint     = "F41411E0225397635C2ECF7DE6103DB7886C5D85"
      cert_valid_from     = "2025-05-15"
      cert_valid_to       = "2026-05-16"

      country             = "RU"
      state               = "Moscow"
      locality            = "Moscow"
      email               = "???"
      rdn_serial_number   = "1247700686551"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "79:a7:89:83:7a:15:ba:f7:21:30:7d:48"
      )
}
