import "pe"

rule MAL_Compromised_Cert_RomCom_GlobalSign_1AF334F5EA8DEF7E2A53BF1E {
   meta:
      description         = "Detects RomCom with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-29"
      version             = "1.0"

      hash                = "c388bec860ce843bc16448568d642cc8c3afe127ac09f7758fd2e449c75fd202"
      malware             = "RomCom"
      malware_type        = "Initial access tool"
      malware_notes       = "Malicious executable faking as a PDF"

      signer              = "X, LIMITED LIABILITY COMPANY"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "1a:f3:34:f5:ea:8d:ef:7e:2a:53:bf:1e"
      cert_thumbprint     = "410DAD049512BF2A316BB3E7DBEE13AA2E0DA7C2"
      cert_valid_from     = "2026-01-29"
      cert_valid_to       = "2026-12-10"

      country             = "JP"
      state               = "Tokyo"
      locality            = "Minato"
      email               = "???"
      rdn_serial_number   = "0104-03-028255"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "1a:f3:34:f5:ea:8d:ef:7e:2a:53:bf:1e"
      )
}
