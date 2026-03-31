import "pe"

rule MAL_Compromised_Cert_FakeWallet_Sectigo_0091929DE2700952A16EC4A63D9D815E9D {
   meta:
      description         = "Detects FakeWallet with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-28"
      version             = "1.0"

      hash                = "11b7a18b617876c34d98a8ec362f6a08c3e7308b5e7c6d792d4c417e55ce3814"
      malware             = "FakeWallet"
      malware_type        = "Unknown"
      malware_notes       = "Malicious installer impersonating Electrum XRP wallet"

      signer              = "Hefei Fanchun Cultural Communication Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:91:92:9d:e2:70:09:52:a1:6e:c4:a6:3d:9d:81:5e:9d"
      cert_thumbprint     = "F69C92AD7827043C9D0B5B78A810DE9B3A98FA67"
      cert_valid_from     = "2026-01-28"
      cert_valid_to       = "2027-01-28"

      country             = "CN"
      state               = "Anhui Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91330109MA2HXDJ10C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:91:92:9d:e2:70:09:52:a1:6e:c4:a6:3d:9d:81:5e:9d"
      )
}
