import "pe"

rule MAL_Compromised_Cert_BlackMoon_Certum_2D04350A580D7734D89F471FB36CCE06 {
   meta:
      description         = "Detects BlackMoon with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-23"
      version             = "1.0"

      hash                = "16be51c61a21d1c3ed859cc959ac6bcb052ce19528d05c1cfe3b7e33440f3bb1"
      malware             = "BlackMoon"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "强子硕"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Code Signing 2021 CA"
      cert_serial         = "2d:04:35:0a:58:0d:77:34:d8:9f:47:1f:b3:6c:ce:06"
      cert_thumbprint     = "9de1f68872f49e6c3c5e4cc8f2c256750f6575ab"
      cert_valid_from     = "2026-07-23"
      cert_valid_to       = "2027-07-23"

      country             = "CN"
      state               = "宁夏"
      locality            = "吴忠"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Code Signing 2021 CA" and
         sig.serial == "2d:04:35:0a:58:0d:77:34:d8:9f:47:1f:b3:6c:ce:06"
      )
}
