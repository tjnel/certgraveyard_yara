import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_3300008B04822781012CEC21B6000000008B04 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-27"
      version             = "1.0"

      hash                = "0bb0b14952e2135f1baf67eba4a80dd66db9042274617b3f0871292cd20be460"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "JAVIER MIGUEL GURULE"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:8b:04:82:27:81:01:2c:ec:21:b6:00:00:00:00:8b:04"
      cert_thumbprint     = "75BFC7D4C59FFE769C0107BC5119F09FAEBB3CCA"
      cert_valid_from     = "2026-04-27"
      cert_valid_to       = "2026-04-30"

      country             = "US"
      state               = "Hawaii"
      locality            = "KAPOLEI"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:8b:04:82:27:81:01:2c:ec:21:b6:00:00:00:00:8b:04"
      )
}
