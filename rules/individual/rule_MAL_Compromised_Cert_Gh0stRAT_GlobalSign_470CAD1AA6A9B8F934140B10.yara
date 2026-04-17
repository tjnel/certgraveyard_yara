import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_GlobalSign_470CAD1AA6A9B8F934140B10 {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-08"
      version             = "1.0"

      hash                = "847f95f561958adb3475d70ba927c806e6e7a9f288e1e9bc90e84aad43d01ae1"
      malware             = "Gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "重庆昱泽科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "47:0c:ad:1a:a6:a9:b8:f9:34:14:0b:10"
      cert_thumbprint     = "5C1DA8E5F6F36B6AB6DB77D9DCBB729262765602"
      cert_valid_from     = "2026-04-08"
      cert_valid_to       = "2027-04-09"

      country             = "CN"
      state               = "重庆"
      locality            = "重庆"
      email               = "???"
      rdn_serial_number   = "91500000MAECDB1W2T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "47:0c:ad:1a:a6:a9:b8:f9:34:14:0b:10"
      )
}
