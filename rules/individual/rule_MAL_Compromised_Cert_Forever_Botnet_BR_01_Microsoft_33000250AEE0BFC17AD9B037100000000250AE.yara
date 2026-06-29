import "pe"

rule MAL_Compromised_Cert_Forever_Botnet_BR_01_Microsoft_33000250AEE0BFC17AD9B037100000000250AE {
   meta:
      description         = "Detects Forever Botnet,BR-01 with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-24"
      version             = "1.0"

      hash                = "9832843da2c6057bd8a522820b947e507b1c5560f07c3449ba917592efd5439f"
      malware             = "Forever Botnet,BR-01"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "TMP-Ohjelmatuotanto Oy"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:02:50:ae:e0:bf:c1:7a:d9:b0:37:10:00:00:00:02:50:ae"
      cert_thumbprint     = "EE0F51939305174E739A20C3AF5C259852204402"
      cert_valid_from     = "2026-06-24"
      cert_valid_to       = "2026-06-27"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:02:50:ae:e0:bf:c1:7a:d9:b0:37:10:00:00:00:02:50:ae"
      )
}
