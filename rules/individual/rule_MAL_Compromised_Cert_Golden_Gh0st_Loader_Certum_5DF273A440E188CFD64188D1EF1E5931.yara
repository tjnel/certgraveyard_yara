import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_5DF273A440E188CFD64188D1EF1E5931 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-27"
      version             = "1.0"

      hash                = "a5516a25bc40eb74359b74dccbf7309ffdc173c4a2d44a47f09d62da45f566c8"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "杭州思维宇宙科技有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5d:f2:73:a4:40:e1:88:cf:d6:41:88:d1:ef:1e:59:31"
      cert_thumbprint     = "14E0FCA3F0F656D1AF6EA66E1B2B7C6B4ACD8E2D"
      cert_valid_from     = "2026-04-27"
      cert_valid_to       = "2027-03-03"

      country             = "CN"
      state               = "浙江"
      locality            = "杭州"
      email               = "???"
      rdn_serial_number   = "91330108MACPWGQM5F"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5d:f2:73:a4:40:e1:88:cf:d6:41:88:d1:ef:1e:59:31"
      )
}
