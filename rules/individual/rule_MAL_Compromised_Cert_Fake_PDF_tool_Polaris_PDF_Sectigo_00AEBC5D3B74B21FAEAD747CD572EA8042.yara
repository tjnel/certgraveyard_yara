import "pe"

rule MAL_Compromised_Cert_Fake_PDF_tool_Polaris_PDF_Sectigo_00AEBC5D3B74B21FAEAD747CD572EA8042 {
   meta:
      description         = "Detects Fake PDF tool, Polaris PDF with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-14"
      version             = "1.0"

      hash                = "4f9b91b003525136c176ff4f74e0eae43572f9bcbb07d9e04c12620dd056a3da"
      malware             = "Fake PDF tool, Polaris PDF"
      malware_type        = "Trojan"
      malware_notes       = "This is a tampered-chef style trojanized Inno Setup installer masquerading as a fake \"Polaris PDF\" utility. It drops a malicious DLL (yyj.dll) masquerading as the open-source yyjson library."

      signer              = "Eman Group LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ae:bc:5d:3b:74:b2:1f:ae:ad:74:7c:d5:72:ea:80:42"
      cert_thumbprint     = "5C8C454635703E016095275D1386854C15887C72"
      cert_valid_from     = "2026-01-14"
      cert_valid_to       = "2027-01-14"

      country             = "US"
      state               = "New York"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "7296951"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ae:bc:5d:3b:74:b2:1f:ae:ad:74:7c:d5:72:ea:80:42"
      )
}
