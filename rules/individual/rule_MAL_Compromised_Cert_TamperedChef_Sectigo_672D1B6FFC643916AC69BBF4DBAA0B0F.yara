import "pe"

rule MAL_Compromised_Cert_TamperedChef_Sectigo_672D1B6FFC643916AC69BBF4DBAA0B0F {
   meta:
      description         = "Detects TamperedChef with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-04-04"
      version             = "1.0"

      hash                = "a7666e5aa3c6ecae0295caa7c3f49714eb561d6e1be6807cf1020b79f1902cd0"
      malware             = "TamperedChef"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Animated Productions, LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "67:2d:1b:6f:fc:64:39:16:ac:69:bb:f4:db:aa:0b:0f"
      cert_thumbprint     = "0eeb45e2409b509fcf3021fc7298b877c8cfa5aa"
      cert_valid_from     = "2024-04-04"
      cert_valid_to       = "2025-04-04"

      country             = "US"
      state               = "Kansas"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "67:2d:1b:6f:fc:64:39:16:ac:69:bb:f4:db:aa:0b:0f"
      )
}
