import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_33000895015C8E0366320A9CB8000000089501 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-29"
      version             = "1.0"

      hash                = "d418420aa4accfb887be12a22b277a1ea14a74bbb074debd1dc2cd341117ec1a"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Stalin Fabrico Loor Romero"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:95:01:5c:8e:03:66:32:0a:9c:b8:00:00:00:08:95:01"
      cert_thumbprint     = "EAF99F6612D630F0E09891C6BDE940E52244B3D9"
      cert_valid_from     = "2026-03-29"
      cert_valid_to       = "2026-04-01"

      country             = "US"
      state               = "Texas"
      locality            = "Richmond"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:95:01:5c:8e:03:66:32:0a:9c:b8:00:00:00:08:95:01"
      )
}
