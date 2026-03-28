import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_330008BF7AFB3B5E4631E287B400000008BF7A {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-26"
      version             = "1.0"

      hash                = "f7ffcbb73bf9265ef842966048d7448f395a99e60bee72dd0d230e674d6e218c"
      malware             = "Forever Botnet,BR-01"
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
