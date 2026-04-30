import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_33000618B57FE2CCF0CDC3A0600000000618B5 {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-30"
      version             = "1.0"

      hash                = "d6834a0435dda706850af146ff9d0ea98993958ee401c526e19dafbc507efee0"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:06:18:b5:7f:e2:cc:f0:cd:c3:a0:60:00:00:00:06:18:b5"
      cert_thumbprint     = "8FDE8810C855361EAEB72CF390B4B1B9531ABAF4"
      cert_valid_from     = "2025-12-30"
      cert_valid_to       = "2026-01-02"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:06:18:b5:7f:e2:cc:f0:cd:c3:a0:60:00:00:00:06:18:b5"
      )
}
