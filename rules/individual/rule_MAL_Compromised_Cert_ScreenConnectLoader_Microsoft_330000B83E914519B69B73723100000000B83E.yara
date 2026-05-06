import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330000B83E914519B69B73723100000000B83E {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-03"
      version             = "1.0"

      hash                = "4fac9600c16f6d96ccde322e1ecd9e0915771cef773ad76c338b6bc31db442a9"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CHRISTIAN TORRES"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 03"
      cert_serial         = "33:00:00:b8:3e:91:45:19:b6:9b:73:72:31:00:00:00:00:b8:3e"
      cert_thumbprint     = "E3AA9C7F27EC394471B133DF410B3AF5CC55B536"
      cert_valid_from     = "2026-05-03"
      cert_valid_to       = "2026-05-06"

      country             = "US"
      state               = "Texas"
      locality            = "UNIVERSAL CITY"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 03" and
         sig.serial == "33:00:00:b8:3e:91:45:19:b6:9b:73:72:31:00:00:00:00:b8:3e"
      )
}
