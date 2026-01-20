import "pe"

rule MAL_Compromised_Cert_Traffer_Certum_4B1DE55AF5EE5E01FBC56E094F8959AD {
   meta:
      description         = "Detects Traffer with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-04"
      version             = "1.0"

      hash                = "3afcd68c357bf33815bf7cc04631ddb1204b71347b06e8dc04a00246cb7a08d7"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Fake Microsoft Teams Meeting Launcher"

      signer              = "Taiyuan Yiyu Trading Co., Ltd."
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "4b:1d:e5:5a:f5:ee:5e:01:fb:c5:6e:09:4f:89:59:ad"
      cert_thumbprint     = "BCCD43B323E9CCDA993CC3CA7B4DDE0EFA4E6BC1"
      cert_valid_from     = "2025-12-04"
      cert_valid_to       = "2026-12-04"

      country             = "CN"
      state               = "Shanxi"
      locality            = "Taiyuan"
      email               = "???"
      rdn_serial_number   = "91140105MADC6K7F6C"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "4b:1d:e5:5a:f5:ee:5e:01:fb:c5:6e:09:4f:89:59:ad"
      )
}
