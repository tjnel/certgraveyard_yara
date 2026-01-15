import "pe"

rule MAL_Compromised_Cert_UNK_52_Akira_related_following_Teams_malvertising_Sectigo_239B3B73251BDF4C4EEA5C90DFAAC059 {
   meta:
      description         = "Detects UNK-52,Akira-related following Teams malvertising with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-08"
      version             = "1.0"

      hash                = "a252b2e2e1eb1423cb2781dd194fd5758817157847b3eb18bc86486c2f366643"
      malware             = "UNK-52,Akira-related following Teams malvertising"
      malware_type        = "Loader"
      malware_notes       = "This malware's purpose is to execute a line of base64 and retrieve a remote payload."

      signer              = "Wenzhou Feixun Internet Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "23:9b:3b:73:25:1b:df:4c:4e:ea:5c:90:df:aa:c0:59"
      cert_thumbprint     = "B39874FFCA4BC94F016EE888E2A6EB8A25A544ED"
      cert_valid_from     = "2025-12-08"
      cert_valid_to       = "2026-12-08"

      country             = "CN"
      state               = "Zhejiang Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91330302MA2H91PU2D"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "23:9b:3b:73:25:1b:df:4c:4e:ea:5c:90:df:aa:c0:59"
      )
}
