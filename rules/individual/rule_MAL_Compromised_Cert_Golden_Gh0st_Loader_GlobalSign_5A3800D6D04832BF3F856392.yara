import "pe"

rule MAL_Compromised_Cert_Golden_Gh0st_Loader_GlobalSign_5A3800D6D04832BF3F856392 {
   meta:
      description         = "Detects Golden Gh0st Loader with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-07-30"
      version             = "1.0"

      hash                = "0b37b477af11ec41fb6edbdeb6d9fecaa7b6e95636e036767fe64b029bbcb392"
      malware             = "Golden Gh0st Loader"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "Sichuan Quantianxia Furniture Co., Ltd"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "5a:38:00:d6:d0:48:32:bf:3f:85:63:92"
      cert_thumbprint     = "c450b64c66ecb65468f76cc68426d1de8af7a1fb"
      cert_valid_from     = "2026-07-30"
      cert_valid_to       = "2027-07-31"

      country             = "CN"
      state               = "Sichuan"
      locality            = "Chengdu"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "5a:38:00:d6:d0:48:32:bf:3f:85:63:92"
      )
}
