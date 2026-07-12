import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_3300010A1FC37D40715BFDAEC9000000010A1F {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-15"
      version             = "1.0"

      hash                = "450022431a5d5d5589895b878420747c860a85928d560f48355acbc8825ba744"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xryus Technologies LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:01:0a:1f:c3:7d:40:71:5b:fd:ae:c9:00:00:00:01:0a:1f"
      cert_thumbprint     = "53E8C772728EA5CF88CBFBD07485F73BA9E6BBEC"
      cert_valid_from     = "2026-05-15"
      cert_valid_to       = "2026-05-18"

      country             = "US"
      state               = "Delaware"
      locality            = "Lewes"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:01:0a:1f:c3:7d:40:71:5b:fd:ae:c9:00:00:00:01:0a:1f"
      )
}
