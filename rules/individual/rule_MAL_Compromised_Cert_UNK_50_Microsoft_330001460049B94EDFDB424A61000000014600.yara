import "pe"

rule MAL_Compromised_Cert_UNK_50_Microsoft_330001460049B94EDFDB424A61000000014600 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-22"
      version             = "1.0"

      hash                = "166e853a84048f8dc3af89a8183966e3a9e1cd4c6a0c5a27fefdc7dac52acdd1"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "BEYOND TECHNOLOGIES SRL"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:01:46:00:49:b9:4e:df:db:42:4a:61:00:00:00:01:46:00"
      cert_thumbprint     = "3E9F57E8463180507AAF4F0DEB85F986A4B0D6CF"
      cert_valid_from     = "2026-05-22"
      cert_valid_to       = "2026-05-25"

      country             = "RO"
      state               = "Bucharest"
      locality            = "Bucuresti"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:01:46:00:49:b9:4e:df:db:42:4a:61:00:00:00:01:46:00"
      )
}
