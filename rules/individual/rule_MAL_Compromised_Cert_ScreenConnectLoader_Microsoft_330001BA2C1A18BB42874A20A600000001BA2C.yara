import "pe"

rule MAL_Compromised_Cert_ScreenConnectLoader_Microsoft_330001BA2C1A18BB42874A20A600000001BA2C {
   meta:
      description         = "Detects ScreenConnectLoader with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-05"
      version             = "1.0"

      hash                = "9995ece9f55ebdebfe5e39724144dde85bb401c6294d473266353de333055240"
      malware             = "ScreenConnectLoader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Danielle Hale"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS AOC CA 03"
      cert_serial         = "33:00:01:ba:2c:1a:18:bb:42:87:4a:20:a6:00:00:00:01:ba:2c"
      cert_thumbprint     = "6C9486003FB338A4F7F16D17F28A3DC404F30D3F"
      cert_valid_from     = "2026-06-05"
      cert_valid_to       = "2026-06-08"

      country             = "US"
      state               = "oh"
      locality            = "Cleveland"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS AOC CA 03" and
         sig.serial == "33:00:01:ba:2c:1a:18:bb:42:87:4a:20:a6:00:00:00:01:ba:2c"
      )
}
