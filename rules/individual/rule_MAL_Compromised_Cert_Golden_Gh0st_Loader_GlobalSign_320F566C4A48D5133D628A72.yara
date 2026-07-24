import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_GlobalSign_320F566C4A48D5133D628A72 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-04"
      version             = "1.0"

      hash                = "26fba07c17efbb6c48a2e746e42df1ee26405c6aa557039492553e5bc27598a1"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Unknown"
      malware_notes       = "This was used in the second stage. It is a resigned Tencent Browser application."

      signer              = "Feidelai (Chengdu) Home Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "32:0f:56:6c:4a:48:d5:13:3d:62:8a:72"
      cert_thumbprint     = "6321ef70eb324b04c664b6bef2a6613ba6e8218d"
      cert_valid_from     = "2026-06-04"
      cert_valid_to       = "2027-06-05"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "---"
      rdn_serial_number   = "91510107MACA8G9A46"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "32:0f:56:6c:4a:48:d5:13:3d:62:8a:72"
      )
}
