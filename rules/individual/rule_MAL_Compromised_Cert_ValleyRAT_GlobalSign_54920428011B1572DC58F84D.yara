import "pe"

rule MAL_Compromised_Cert_ValleyRAT_GlobalSign_54920428011B1572DC58F84D {
   meta:
      description         = "Detects ValleyRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-20"
      version             = "1.0"

      hash                = "1c46675149b0f4d926783c855e860b20548568849cdec941a62abb72534d1e68"
      malware             = "ValleyRAT"
      malware_type        = "Remote access tool"
      malware_notes       = "This version was disguised as a flash player installer. Read more about ValleyRAT here: https://research.checkpoint.com/2025/cracking-valleyrat-from-builder-secrets-to-kernel-rootkits/"

      signer              = "哈尔滨瑚板颂电子科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "54:92:04:28:01:1b:15:72:dc:58:f8:4d"
      cert_thumbprint     = "8D61A18D80A316E0791FAF1CB8AAFF42B8B621BA"
      cert_valid_from     = "2025-11-20"
      cert_valid_to       = "2026-11-21"

      country             = "CN"
      state               = "黑龙江"
      locality            = "哈尔滨"
      email               = "???"
      rdn_serial_number   = "91230109MAE08WRJ07"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "54:92:04:28:01:1b:15:72:dc:58:f8:4d"
      )
}
