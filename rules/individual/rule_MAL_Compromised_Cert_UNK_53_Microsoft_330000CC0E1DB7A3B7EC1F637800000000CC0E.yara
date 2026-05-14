import "pe"

rule MAL_Compromised_Cert_UNK_53_Microsoft_330000CC0E1DB7A3B7EC1F637800000000CC0E {
   meta:
      description         = "Detects UNK-53 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-07"
      version             = "1.0"

      hash                = "63a552f1683cdaf569b1d72c565524a3d783da996fa0d37076a6018c6a256e7f"
      malware             = "UNK-53"
      malware_type        = "Remote access tool"
      malware_notes       = "Telegram based rat, with C2 idantre[.]com"

      signer              = "Benjamin Tillinger"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:00:cc:0e:1d:b7:a3:b7:ec:1f:63:78:00:00:00:00:cc:0e"
      cert_thumbprint     = "EB6EF95EE5EB587CC2A4FA605443E0CAF6E1DA5B"
      cert_valid_from     = "2026-05-07"
      cert_valid_to       = "2026-05-10"

      country             = "US"
      state               = "Florida"
      locality            = "Merritt Island"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:00:cc:0e:1d:b7:a3:b7:ec:1f:63:78:00:00:00:00:cc:0e"
      )
}
