import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330008C821DB63CCCBAD133D9400000008C821 {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-28"
      version             = "1.0"

      hash                = "56d46f34948f322312e9a150800cc5b9c947f2ccc82a5b96568be4b50b30e551"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Sharp Tavyn"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 01"
      cert_serial         = "33:00:08:c8:21:db:63:cc:cb:ad:13:3d:94:00:00:00:08:c8:21"
      cert_thumbprint     = "0110B90610A1C021448DEF930897456B50CDDC24"
      cert_valid_from     = "2026-03-28"
      cert_valid_to       = "2026-03-31"

      country             = "US"
      state               = "Oklahoma"
      locality            = "Ringling"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 01" and
         sig.serial == "33:00:08:c8:21:db:63:cc:cb:ad:13:3d:94:00:00:00:08:c8:21"
      )
}
