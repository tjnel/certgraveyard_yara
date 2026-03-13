import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330007FEC703614EE8690370C200000007FEC7 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-25"
      version             = "1.0"

      hash                = "bedde013f139403b9767023e7145caa16e854a7072eec022415e48dab698999d"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "DIGITAL ADVERTISING BUSINESS INFLUENCERS S.R.L."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:07:fe:c7:03:61:4e:e8:69:03:70:c2:00:00:00:07:fe:c7"
      cert_thumbprint     = "00365E3A5E98D6FD3BFA2BA8D6CC5EB3B0D3E9F1"
      cert_valid_from     = "2026-02-25"
      cert_valid_to       = "2026-02-28"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:07:fe:c7:03:61:4e:e8:69:03:70:c2:00:00:00:07:fe:c7"
      )
}
