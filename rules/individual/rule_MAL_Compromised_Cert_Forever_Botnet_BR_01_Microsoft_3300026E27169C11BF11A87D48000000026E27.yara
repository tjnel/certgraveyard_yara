import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_3300026E27169C11BF11A87D48000000026E27 {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-27"
      version             = "1.0"

      hash                = "57dac1b0fa9e682d746a942301e285c8cf030e42a00ec79aac16400eb65bce64"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TMP-Ohjelmatuotanto Oy"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:02:6e:27:16:9c:11:bf:11:a8:7d:48:00:00:00:02:6e:27"
      cert_thumbprint     = "915C2EA2BC19CF2027B11B786BD5B8DCE77CE98B"
      cert_valid_from     = "2026-06-27"
      cert_valid_to       = "2026-06-30"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:02:6e:27:16:9c:11:bf:11:a8:7d:48:00:00:00:02:6e:27"
      )
}
