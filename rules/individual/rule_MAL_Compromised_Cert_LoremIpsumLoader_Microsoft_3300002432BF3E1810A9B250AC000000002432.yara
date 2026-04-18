import "pe"

rule MAL_Compromised_Cert_LoremIpsumLoader_Microsoft_3300002432BF3E1810A9B250AC000000002432 {
   meta:
      description         = "Detects LoremIpsumLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-16"
      version             = "1.0"

      hash                = "aa9c31a09d58142f32bf306fbfc628d14467a68e05bb55ef5c2fde98b84b0688"
      malware             = "LoremIpsumLoader"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "TREY TROTTER"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:24:32:bf:3e:18:10:a9:b2:50:ac:00:00:00:00:24:32"
      cert_thumbprint     = "00865059D3E48DF80839A2B4D101F35E0F102456"
      cert_valid_from     = "2026-04-16"
      cert_valid_to       = "2026-04-19"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:24:32:bf:3e:18:10:a9:b2:50:ac:00:00:00:00:24:32"
      )
}
