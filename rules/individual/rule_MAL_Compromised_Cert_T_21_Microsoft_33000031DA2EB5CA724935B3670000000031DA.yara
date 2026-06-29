import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_33000031DA2EB5CA724935B3670000000031DA {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-17"
      version             = "1.0"

      hash                = "ac9963695eb09277a356e8e14b3cd11415533e2d75e0e08a7bf1989b7eeed389"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TAYLOR ASHER"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:31:da:2e:b5:ca:72:49:35:b3:67:00:00:00:00:31:da"
      cert_thumbprint     = "3054D941313B0DD4297A4AFC9E20A6A41C8DB689"
      cert_valid_from     = "2026-04-17"
      cert_valid_to       = "2026-04-20"

      country             = "US"
      state               = "Alaska"
      locality            = "TALKEETNA"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:31:da:2e:b5:ca:72:49:35:b3:67:00:00:00:00:31:da"
      )
}
