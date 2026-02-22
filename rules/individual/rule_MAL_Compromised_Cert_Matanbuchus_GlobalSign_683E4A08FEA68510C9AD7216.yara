import "pe"

rule MAL_Compromised_Cert_Matanbuchus_GlobalSign_683E4A08FEA68510C9AD7216 {
   meta:
      description         = "Detects Matanbuchus with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-01"
      version             = "1.0"

      hash                = "0574a50df76a0103fd78d83e34ab9d9ee4a29560c17c378e40404bb0a32ccf7d"
      malware             = "Matanbuchus"
      malware_type        = "Initial access tool"
      malware_notes       = "File was named Rate_Confirmation_757389.exe and is part of carrier targeting."

      signer              = "OOO VOLSTROIVEST"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "68:3e:4a:08:fe:a6:85:10:c9:ad:72:16"
      cert_thumbprint     = "D1CAB8EDA5CFB313B17F967A8074B45B39D5A466"
      cert_valid_from     = "2025-12-01"
      cert_valid_to       = "2026-12-02"

      country             = "RU"
      state               = "Vologda Oblast"
      locality            = "Vologda"
      email               = "geroev1967@mail.ru"
      rdn_serial_number   = "1193525011866"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "68:3e:4a:08:fe:a6:85:10:c9:ad:72:16"
      )
}
