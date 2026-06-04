import "pe"

rule MAL_Compromised_Cert_ValleyRAT_GlobalSign_2686B9982E46DA7E3E0A1D56 {
   meta:
      description         = "Detects ValleyRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-05-16"
      version             = "1.0"

      hash                = "532e97b35149db5010be30f6619d76e1e987c29133416f87a860ff886b141d3c"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Morning Leap & Cazo Electronics Technology Co., Ltd."
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "26:86:b9:98:2e:46:da:7e:3e:0a:1d:56"
      cert_thumbprint     = "69E050F63735CA4A1BCF5A21D3D64BDAB9C0BF42"
      cert_valid_from     = "2024-05-16"
      cert_valid_to       = "2025-05-16"

      country             = "CN"
      state               = "Hebei"
      locality            = "Cangzhou"
      email               = "???"
      rdn_serial_number   = "91130922MA0G8AN920"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "26:86:b9:98:2e:46:da:7e:3e:0a:1d:56"
      )
}
