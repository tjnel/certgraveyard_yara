import "pe"

rule MAL_Compromised_Cert_BackdoorElectron_Microsoft_330008BF7AFB3B5E4631E287B400000008BF7A {
   meta:
      description         = "Detects BackdoorElectron with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-26"
      version             = "1.0"

      hash                = "932620b4b6f1d2336b6bbb6e11ad85391cce459db49552dfeef86fb5504acf03"
      malware             = "BackdoorElectron"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Stalin Fabrico Loor Romero"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:bf:7a:fb:3b:5e:46:31:e2:87:b4:00:00:00:08:bf:7a"
      cert_thumbprint     = "955F3C5831E143164BBFB554640FF810033D45CF"
      cert_valid_from     = "2026-03-26"
      cert_valid_to       = "2026-03-29"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:bf:7a:fb:3b:5e:46:31:e2:87:b4:00:00:00:08:bf:7a"
      )
}
