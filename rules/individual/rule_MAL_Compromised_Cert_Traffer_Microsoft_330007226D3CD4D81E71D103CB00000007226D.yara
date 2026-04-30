import "pe"

rule MAL_Compromised_Cert_Traffer_Microsoft_330007226D3CD4D81E71D103CB00000007226D {
   meta:
      description         = "Detects Traffer with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-28"
      version             = "1.0"

      hash                = "46f59eb0dc68d4e5511446bd2ae7fb723a04dce72322f0786b43463c53bd1f64"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Marker Hill Construction Inc"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:07:22:6d:3c:d4:d8:1e:71:d1:03:cb:00:00:00:07:22:6d"
      cert_thumbprint     = "F257123388DD089DEF50AED28D913DD606F0EC76"
      cert_valid_from     = "2026-02-28"
      cert_valid_to       = "2026-03-03"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:07:22:6d:3c:d4:d8:1e:71:d1:03:cb:00:00:00:07:22:6d"
      )
}
