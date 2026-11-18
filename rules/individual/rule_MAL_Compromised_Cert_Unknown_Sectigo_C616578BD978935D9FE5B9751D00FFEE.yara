import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_C616578BD978935D9FE5B9751D00FFEE {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-23"
      version             = "1.0"

      hash                = "fe9829f1c102a79b4ca33c8c8bda8ef2236dc94c6d1de88249c89e82681adc8c"
      malware             = "Unknown"
      malware_type        = "Backdoor"
      malware_notes       = "https://rogueauthority.org/signed-fake-zscaler-tunnel-go-backdoor"

      signer              = "MARQUEE AUDIO VISUAL LIMITED"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "c6:16:57:8b:d9:78:93:5d:9f:e5:b9:75:1d:00:ff:ee"
      cert_thumbprint     = "b56b946b2d9fb06ac86b92c83b1d3ad608d6abab"
      cert_valid_from     = "2026-10-23"
      cert_valid_to       = "2027-10-23"

      country             = "IE"
      state               = "Dublin"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "c6:16:57:8b:d9:78:93:5d:9f:e5:b9:75:1d:00:ff:ee"
      )
}
