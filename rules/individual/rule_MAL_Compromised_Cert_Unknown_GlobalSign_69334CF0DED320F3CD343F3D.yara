import "pe"

rule MAL_Compromised_Cert_Unknown_GlobalSign_69334CF0DED320F3CD343F3D {
   meta:
      description         = "Detects Unknown with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-07"
      version             = "1.0"

      hash                = "a967b46481f77ce9bdd6e57afe858943dd5c03e8810a95e3223c9b2ccec06ec6"
      malware             = "Unknown"
      malware_type        = "Backdoor"
      malware_notes       = "https://rogueauthority.org/signed-touch-controller-mtls-stager"

      signer              = "AirTiki ApS"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "69:33:4c:f0:de:d3:20:f3:cd:34:3f:3d"
      cert_thumbprint     = "f8908f37cb07e4324c69d19974ad8f25a1e1cc81"
      cert_valid_from     = "2026-08-07"
      cert_valid_to       = "2027-08-08"

      country             = "DK"
      state               = "Region Zealand"
      locality            = "Nysted"
      email               = "ole@airtioki.com"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "69:33:4c:f0:de:d3:20:f3:cd:34:3f:3d"
      )
}
