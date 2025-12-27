import "pe"

rule MAL_Compromised_Cert_Unknown_Microsoft_330005E4648C6BF731C5D00F3300000005E464 {
   meta:
      description         = "Detects Unknown with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-20"
      version             = "1.0"

      hash                = "3d1763b037e66bbde222125a21b23fc24abd76ebab40589748ac69e2f37c27fc"
      malware             = "Unknown"
      malware_type        = "Infostealer"
      malware_notes       = "Someone modified the legitimate EmEditor website to distribute this infostealer. An analysis of the malware can be found here: https://mp.weixin.qq.com/s/M1-UdMaGflhkuqet0K1gqg"

      signer              = "WALSHAM INVESTMENTS LIMITED"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 01"
      cert_serial         = "33:00:05:e4:64:8c:6b:f7:31:c5:d0:0f:33:00:00:00:05:e4:64"
      cert_thumbprint     = "6BDA2A57F1E2BBC235DCAF16728DF2655EBF69C1"
      cert_valid_from     = "2025-12-20"
      cert_valid_to       = "2025-12-23"

      country             = "GB"
      state               = "Essex"
      locality            = "Grays"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 01" and
         sig.serial == "33:00:05:e4:64:8c:6b:f7:31:c5:d0:0f:33:00:00:00:05:e4:64"
      )
}
