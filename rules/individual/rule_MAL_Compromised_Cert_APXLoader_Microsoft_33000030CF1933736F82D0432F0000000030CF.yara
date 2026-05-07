import "pe"

rule MAL_Compromised_Cert_APXLoader_Microsoft_33000030CF1933736F82D0432F0000000030CF {
   meta:
      description         = "Detects APXLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-17"
      version             = "1.0"

      hash                = "52be7c85eb9545866782209d7b2a6e0ba23111ca03285ff1eab0fe2878c29d6e"
      malware             = "APXLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "SOPHIA MONGILLO"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:30:cf:19:33:73:6f:82:d0:43:2f:00:00:00:00:30:cf"
      cert_thumbprint     = "964EC367FAE8447C332A9CC3BE37B31D9B435C9E"
      cert_valid_from     = "2026-04-17"
      cert_valid_to       = "2026-04-20"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:30:cf:19:33:73:6f:82:d0:43:2f:00:00:00:00:30:cf"
      )
}
