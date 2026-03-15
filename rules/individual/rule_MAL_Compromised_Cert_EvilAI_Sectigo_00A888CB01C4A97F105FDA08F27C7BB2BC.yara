import "pe"

rule MAL_Compromised_Cert_EvilAI_Sectigo_00A888CB01C4A97F105FDA08F27C7BB2BC {
   meta:
      description         = "Detects EvilAI with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-29"
      version             = "1.0"

      hash                = "b18e84c03195b6e8e4b92c59a2845d7118e915c2638c2ca524fbeb10c81ea83b"
      malware             = "EvilAI"
      malware_type        = "Browser Hijacker"
      malware_notes       = "AI generated report- https://github.com/Squiblydoo/Remnux_Reports/blob/main/Reports%20by%20hash/b18e84c03195b6e8e4b92c59a2845d7118e915c2638c2ca524fbeb10c81ea83b_FlashTestInstaller.md"

      signer              = "Kartos Gale LTD"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a8:88:cb:01:c4:a9:7f:10:5f:da:08:f2:7c:7b:b2:bc"
      cert_thumbprint     = "3B95B58BE7A6F83A124FFD52E5DA2E49046CE8A1"
      cert_valid_from     = "2025-12-29"
      cert_valid_to       = "2026-12-29"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a8:88:cb:01:c4:a9:7f:10:5f:da:08:f2:7c:7b:b2:bc"
      )
}
