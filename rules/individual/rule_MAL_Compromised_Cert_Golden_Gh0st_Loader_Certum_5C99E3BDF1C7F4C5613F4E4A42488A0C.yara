import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_Certum_5C99E3BDF1C7F4C5613F4E4A42488A0C {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-08-27"
      version             = "1.0"

      hash                = "1c5f7d730c6cdff7b0027609aa654da0d8602002e4e2d44d05a9c544b6c54b1e"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Dongguan Fandi Network Technology Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "5c:99:e3:bd:f1:c7:f4:c5:61:3f:4e:4a:42:48:8a:0c"
      cert_thumbprint     = "f5446c857e779657dccc8765fbfb8b4605decd7e"
      cert_valid_from     = "2026-08-27"
      cert_valid_to       = "2027-08-27"

      country             = "CN"
      state               = "广东省"
      locality            = "东莞市"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "5c:99:e3:bd:f1:c7:f4:c5:61:3f:4e:4a:42:48:8a:0c"
      )
}
