import "pe"

rule MAL_Compromised_Cert_ValleyRAT_GlobalSign_49A710D6C41DA0A7CAC7F97A {
   meta:
      description         = "Detects ValleyRAT with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-04-08"
      version             = "1.0"

      hash                = "bddd6923f088a7a6847237b420c118473ab418d4de2772a35991402d5b0ab0e8"
      malware             = "ValleyRAT"
      malware_type        = "Unknown"
      malware_notes       = "Valley RAT impersonating WPS Office. C2 - 108.187.7.232:6666"

      signer              = "武汉市芙樾琳网络科技有限公司"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "49:a7:10:d6:c4:1d:a0:a7:ca:c7:f9:7a"
      cert_thumbprint     = "10C27BE3C759013F25901C68F0A633468742CA0E"
      cert_valid_from     = "2025-04-08"
      cert_valid_to       = "2026-04-09"

      country             = "CN"
      state               = "湖北省"
      locality            = "武汉市"
      email               = "???"
      rdn_serial_number   = "91420116MAEEPPAC1G"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "49:a7:10:d6:c4:1d:a0:a7:ca:c7:f9:7a"
      )
}
