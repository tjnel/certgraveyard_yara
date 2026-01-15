import "pe"

rule MAL_Compromised_Cert_HijackLoader_ShadowLadder_Microsoft_33000660F0D638FC46189CF1820000000660F0 {
   meta:
      description         = "Detects HijackLoader, ShadowLadder with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-13"
      version             = "1.0"

      hash                = "f154fa45aab0fce2d7eaae7b733f3d59ac9cb6d3421705d7d26a1f89e5e7001f"
      malware             = "HijackLoader, ShadowLadder"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "FOCUS DIGITAL AGENCY SP Z O O"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:06:60:f0:d6:38:fc:46:18:9c:f1:82:00:00:00:06:60:f0"
      cert_thumbprint     = "FBCAD08E430911143E201C25A73FCFDC031049FE"
      cert_valid_from     = "2026-01-13"
      cert_valid_to       = "2026-01-16"

      country             = "PL"
      state               = "Mazowieckie"
      locality            = "Warszawa"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:06:60:f0:d6:38:fc:46:18:9c:f1:82:00:00:00:06:60:f0"
      )
}
