import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_3300012E4C6BA0B3FEB1135E87000000012E4C {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-19"
      version             = "1.0"

      hash                = "37484cf418468097d4a1dc6588f310a08d4779462b551d29a19fd336fbe7e83e"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Palacios Edgar"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:01:2e:4c:6b:a0:b3:fe:b1:13:5e:87:00:00:00:01:2e:4c"
      cert_thumbprint     = "CF63DB28A6F8F9BA3EB72947C36B9B60519907A7"
      cert_valid_from     = "2026-05-19"
      cert_valid_to       = "2026-05-22"

      country             = "US"
      state               = "Texas"
      locality            = "San Antonio"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:01:2e:4c:6b:a0:b3:fe:b1:13:5e:87:00:00:00:01:2e:4c"
      )
}
