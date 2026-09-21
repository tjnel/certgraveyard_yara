import "pe"

rule MAL_Compromised_Cert_SideWinder_Microsoft_330005B76B073C59FD6D7793C100000005B76B {
   meta:
      description         = "Detects SideWinder with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-08"
      version             = "1.0"

      hash                = "b6900314a090193140f85e698ef523d1c64769064c46aa2471ffc482a59f1f02"
      malware             = "SideWinder"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Alysen Mendez"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:05:b7:6b:07:3c:59:fd:6d:77:93:c1:00:00:00:05:b7:6b"
      cert_thumbprint     = "2256420b9a569477acd6dec04e6ff68b1dadbc8f"
      cert_valid_from     = "2026-09-08"
      cert_valid_to       = "2026-09-11"

      country             = "US"
      state               = "New Jersey"
      locality            = "LITTLE FERRY"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:05:b7:6b:07:3c:59:fd:6d:77:93:c1:00:00:00:05:b7:6b"
      )
}
