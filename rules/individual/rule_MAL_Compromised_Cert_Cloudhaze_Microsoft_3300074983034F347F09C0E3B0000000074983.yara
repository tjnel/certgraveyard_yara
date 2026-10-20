import "pe"

rule MAL_Compromised_Cert_Cloudhaze_Microsoft_3300074983034F347F09C0E3B0000000074983 {
   meta:
      description         = "Detects Cloudhaze with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-30"
      version             = "1.0"

      hash                = "f9ff28b32522bf4ac0e8f9fa1b392ce43bd26d0b6b70d4c521a2ad67f4a8cbed"
      malware             = "Cloudhaze"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "CYBERTEK SUPPORT LLC"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 04"
      cert_serial         = "33:00:07:49:83:03:4f:34:7f:09:c0:e3:b0:00:00:00:07:49:83"
      cert_thumbprint     = "f8d2cc5747e0d90006cbf7b6a2b83605ec416d19"
      cert_valid_from     = "2026-09-30"
      cert_valid_to       = "2026-10-03"

      country             = "US"
      state               = "Florida"
      locality            = "Tamarac"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 04" and
         sig.serial == "33:00:07:49:83:03:4f:34:7f:09:c0:e3:b0:00:00:00:07:49:83"
      )
}
