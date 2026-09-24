import "pe"

rule MAL_Compromised_Cert_ValleyRAT_Certum_367ED53E788F0A17FDFC5D47FD784914 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (Certum)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-30"
      version             = "1.0"

      hash                = "cb849c2c9f9737b3550b615c2b2d9705eac028d959228ed6b3d32943f7803a50"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = "C2 -134.122.139.114:8080"

      signer              = "抚顺琴安德超商贸有限公司"
      cert_issuer_short   = "Certum"
      cert_issuer         = "Certum Extended Validation Code Signing 2021 CA"
      cert_serial         = "36:7e:d5:3e:78:8f:0a:17:fd:fc:5d:47:fd:78:49:14"
      cert_thumbprint     = "64f79870fd7e1c4057fc880d024e7edf719b8cc6"
      cert_valid_from     = "2026-01-30"
      cert_valid_to       = "2027-01-30"

      country             = "CN"
      state               = "辽宁"
      locality            = "抚顺"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Certum Extended Validation Code Signing 2021 CA" and
         sig.serial == "36:7e:d5:3e:78:8f:0a:17:fd:fc:5d:47:fd:78:49:14"
      )
}
