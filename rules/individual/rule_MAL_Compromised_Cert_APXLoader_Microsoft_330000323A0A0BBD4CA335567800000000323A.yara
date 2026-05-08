import "pe"

rule MAL_Compromised_Cert_APXLoader_Microsoft_330000323A0A0BBD4CA335567800000000323A {
   meta:
      description         = "Detects APXLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-17"
      version             = "1.0"

      hash                = "b35e09bb090cbd52310e98b9bbbb303eea24eb8d468af00d8a55f8a38cecccd8"
      malware             = "APXLoader"
      malware_type        = "Loader"
      malware_notes       = ""

      signer              = "Phillips Mcwilliams"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:00:32:3a:0a:0b:bd:4c:a3:35:56:78:00:00:00:00:32:3a"
      cert_thumbprint     = "6B6A029A3AC80296796B22EB7B9788A32E9368D6"
      cert_valid_from     = "2026-04-17"
      cert_valid_to       = "2026-04-20"

      country             = "US"
      state               = "South Carolina"
      locality            = "Columbia"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:00:32:3a:0a:0b:bd:4c:a3:35:56:78:00:00:00:00:32:3a"
      )
}
