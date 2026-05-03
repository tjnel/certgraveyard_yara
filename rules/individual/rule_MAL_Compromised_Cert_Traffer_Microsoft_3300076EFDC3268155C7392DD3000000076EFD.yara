import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_3300076EFDC3268155C7392DD3000000076EFD {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-15"
      version             = "1.0"

      hash                = "9e6230c0ce510686d92ce9b866c9448349bccdd20418a6b11e828fdb88de59f4"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:6e:fd:c3:26:81:55:c7:39:2d:d3:00:00:00:07:6e:fd"
      cert_thumbprint     = "7653EDCD83E70D7FEB2D30A99378B9ABA8680AD7"
      cert_valid_from     = "2026-03-15"
      cert_valid_to       = "2026-03-18"

      country             = "US"
      state               = "Colorado"
      locality            = "Denver"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:6e:fd:c3:26:81:55:c7:39:2d:d3:00:00:00:07:6e:fd"
      )
}
