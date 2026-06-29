import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_3300017BDB4B06B0CD1F392EC8000000017BDB {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-30"
      version             = "1.0"

      hash                = "2c4fa0b25026eed775185ae41a69f7a3d4bad8c43792638af126fe8f23f8754a"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MARKE SOLUTIONS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 04"
      cert_serial         = "33:00:01:7b:db:4b:06:b0:cd:1f:39:2e:c8:00:00:00:01:7b:db"
      cert_thumbprint     = "0D92DE4EBDF545DC5ABBFFEE559DCCD019BD9877"
      cert_valid_from     = "2026-05-30"
      cert_valid_to       = "2026-06-02"

      country             = "GB"
      state               = "Warwickshire"
      locality            = "ALCESTER"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 04" and
         sig.serial == "33:00:01:7b:db:4b:06:b0:cd:1f:39:2e:c8:00:00:00:01:7b:db"
      )
}
