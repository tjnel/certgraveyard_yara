import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_GlobalSign_74B936AB655DB6CA62761A5C {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-07-09"
      version             = "1.0"

      hash                = "4de8a71b4e5e37f040532aaf31908311910f449c1a64db9141a485960bbae534"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "合肥亲爱的译官信息科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "74:b9:36:ab:65:5d:b6:ca:62:76:1a:5c"
      cert_thumbprint     = "25745917F9D93F19CF8C796B660A9A27E3FA3833"
      cert_valid_from     = "2024-07-09"
      cert_valid_to       = "2025-08-14"

      country             = "CN"
      state               = "安徽"
      locality            = "合肥"
      email               = "???"
      rdn_serial_number   = "91340100MA8PA6TBXY"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "74:b9:36:ab:65:5d:b6:ca:62:76:1a:5c"
      )
}
