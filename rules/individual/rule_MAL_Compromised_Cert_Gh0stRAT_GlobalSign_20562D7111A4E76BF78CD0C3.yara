import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_GlobalSign_20562D7111A4E76BF78CD0C3 {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-06-22"
      version             = "1.0"

      hash                = "2ac8a1f38889ab3d80f71399cbdc509e1cb3ca8b687fb4a9ee96f3d9c81f3bf1"
      malware             = "Gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "上海相椿科技中心"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "20:56:2d:71:11:a4:e7:6b:f7:8c:d0:c3"
      cert_thumbprint     = "0fcc703146b5a41c2c6ad14b6667c73ed8b20342"
      cert_valid_from     = "2026-06-22"
      cert_valid_to       = "2027-06-19"

      country             = "CN"
      state               = "上海"
      locality            = "上海"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "20:56:2d:71:11:a4:e7:6b:f7:8c:d0:c3"
      )
}
