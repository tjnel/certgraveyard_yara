import "pe"

rule MAL_Compromised_Cert_Trojan_EmEditor_Microsoft_330005E2E648E24BC51921E7C200000005E2E6 {
   meta:
      description         = "Detects Trojan EmEditor with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-21"
      version             = "1.0"

      hash                = "4bea333d3d2f2a32018cd6afe742c3b25bfcc6bfe8963179dad3940305b13c98"
      malware             = "Trojan EmEditor"
      malware_type        = "Infostealer"
      malware_notes       = "Someone modified the legitimate EmEditor website to distribute this infostealer. An analysis of the malware can be found here: https://mp.weixin.qq.com/s/M1-UdMaGflhkuqet0K1gqg"

      signer              = "WALSHAM INVESTMENTS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:05:e2:e6:48:e2:4b:c5:19:21:e7:c2:00:00:00:05:e2:e6"
      cert_thumbprint     = "8FF6A92D47F212725D4A77A9600B18430058B2C2"
      cert_valid_from     = "2025-12-21"
      cert_valid_to       = "2025-12-24"

      country             = "GB"
      state               = "Essex"
      locality            = "Grays"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:05:e2:e6:48:e2:4b:c5:19:21:e7:c2:00:00:00:05:e2:e6"
      )
}
