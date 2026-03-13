import "pe"

rule MAL_Compromised_Cert_VariantLoader_Microsoft_3300076278B598C0087FC36AA1000000076278 {
   meta:
      description         = "Detects VariantLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-11"
      version             = "1.0"

      hash                = "86cdf456219e2e962dc073b413c6d264db21938f9d0534aeb68422d0d82f4f01"
      malware             = "VariantLoader"
      malware_type        = "Unknown"
      malware_notes       = "C2: 188.137.246.189"

      signer              = "DIGITAL ADVERTISING BUSINESS INFLUENCERS S.R.L."
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:62:78:b5:98:c0:08:7f:c3:6a:a1:00:00:00:07:62:78"
      cert_thumbprint     = "521EE205DCCD2F4F8EFCD66FBFEC0962EB04627E"
      cert_valid_from     = "2026-03-11"
      cert_valid_to       = "2026-03-14"

      country             = "RO"
      state               = "Brasov"
      locality            = "Brasov"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:62:78:b5:98:c0:08:7f:c3:6a:a1:00:00:00:07:62:78"
      )
}
