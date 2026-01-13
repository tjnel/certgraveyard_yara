import "pe"

rule MAL_Compromised_Cert_UNK_50_GlobalSign_62CBF575C5F8A7A20BBF1CB1 {
   meta:
      description         = "Detects UNK-50 with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-15"
      version             = "1.0"

      hash                = "4c20c6bedd49d9672a061a2d662d2169487c6243de083f3a2246f26ab730b2e8"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Südpack Verpackungen SE & Co. KG"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "62:cb:f5:75:c5:f8:a7:a2:0b:bf:1c:b1"
      cert_thumbprint     = "04E2C0BED678211577AB864D4A2303A819FF2EFE"
      cert_valid_from     = "2025-12-15"
      cert_valid_to       = "2026-12-16"

      country             = "AT"
      state               = "Wien"
      locality            = "Wien"
      email               = "???"
      rdn_serial_number   = "466845m"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "62:cb:f5:75:c5:f8:a7:a2:0b:bf:1c:b1"
      )
}
