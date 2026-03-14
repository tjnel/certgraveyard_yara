import "pe"

rule MAL_Compromised_Cert_RomCom_GlobalSign_150D2E1FF959E364F325EF47 {
   meta:
      description         = "Detects RomCom with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-28"
      version             = "1.0"

      hash                = "df643bcbb3b16aededf7f78aab20f7c16cc1abd2567952eec2e575061bb4427b"
      malware             = "RomCom"
      malware_type        = "Initial access tool"
      malware_notes       = ""

      signer              = "Adal-Koom Limited Liability Company"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "15:0d:2e:1f:f9:59:e3:64:f3:25:ef:47"
      cert_thumbprint     = "133844C9A4691B6C0A72C84787FBF9B7E9B57DE9"
      cert_valid_from     = "2026-02-28"
      cert_valid_to       = "2027-02-20"

      country             = "KG"
      state               = "Osh"
      locality            = "Osh"
      email               = "urmatbekjaparov@outlook.com"
      rdn_serial_number   = "171572-3310-OOO"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "15:0d:2e:1f:f9:59:e3:64:f3:25:ef:47"
      )
}
