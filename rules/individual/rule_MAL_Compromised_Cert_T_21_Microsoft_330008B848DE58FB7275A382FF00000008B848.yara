import "pe"

rule MAL_Compromised_Cert_T_21_Microsoft_330008B848DE58FB7275A382FF00000008B848 {
   meta:
      description         = "Detects T-21 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-06"
      version             = "1.0"

      hash                = "6efa9cd8415265024059a63ef1cb4ac6b060f6949805bc5849f73d46299a15a0"
      malware             = "T-21"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "NATHAN RADER"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 02"
      cert_serial         = "33:00:08:b8:48:de:58:fb:72:75:a3:82:ff:00:00:00:08:b8:48"
      cert_thumbprint     = "5FFE3A61F975E6B860F073A0B7553E3F09734988"
      cert_valid_from     = "2026-04-06"
      cert_valid_to       = "2026-04-09"

      country             = "US"
      state               = "Alaska"
      locality            = "ANCHORAGE"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 02" and
         sig.serial == "33:00:08:b8:48:de:58:fb:72:75:a3:82:ff:00:00:00:08:b8:48"
      )
}
