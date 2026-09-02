import "pe"

rule MAL_Compromised_Cert_Gh0stRAT_GlobalSign_5800BB414C3F683B564E3FCA {
   meta:
      description         = "Detects Gh0stRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-05-29"
      version             = "1.0"

      hash                = "c51c121f3b387a7c38efdc406fb1be58a08bf95c49753091d4fd3b965008a3c0"
      malware             = "Gh0stRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "合肥集凯电子商务有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "58:00:bb:41:4c:3f:68:3b:56:4e:3f:ca"
      cert_thumbprint     = "09faa6aa8f16684987cd733ed7410e43b86666db"
      cert_valid_from     = "2026-05-29"
      cert_valid_to       = "2027-05-30"

      country             = "CN"
      state               = "安徽"
      locality            = "合肥"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "58:00:bb:41:4c:3f:68:3b:56:4e:3f:ca"
      )
}
