import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_33000B984F3750AC5EDF9E78BA0000000B984F {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-11-08"
      version             = "1.0"

      hash                = "32b5b5f419d97ff94bfb7ddc647b331533ec53c1ff3646ec55adbca9d3ccd658"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Tony Roman"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:0b:98:4f:37:50:ac:5e:df:9e:78:ba:00:00:00:0b:98:4f"
      cert_thumbprint     = "953d06f144a54dab7d324bc42b86eef86827aece"
      cert_valid_from     = "2026-11-08"
      cert_valid_to       = "2026-11-11"

      country             = "US"
      state               = "nv"
      locality            = "LAS VEGAS"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:0b:98:4f:37:50:ac:5e:df:9e:78:ba:00:00:00:0b:98:4f"
      )
}
