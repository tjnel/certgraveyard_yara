import "pe"

rule MAL_Compromised_Cert_Trojan_EmEditor_download_link_supply_chain_Microsoft_3300061FCA4D5F667DCB02B9E7000000061FCA {
   meta:
      description         = "Detects Trojan EmEditor download link supply chain with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-31"
      version             = "1.0"

      hash                = "da59acc764bbd6b576bef6b1b9038f592ad4df0eed894b0fbd3931f733622a1a"
      malware             = "Trojan EmEditor download link supply chain"
      malware_type        = "Initial access tool"
      malware_notes       = "EmEditor's website was modified to download this file. In sandbox analysis, it attempts to read and execute PowerShell from a malicious domain: https://app.any.run/tasks/6cfbe2bc-1771-4869-8ae2-a50d3ce362c0"

      signer              = "GRH PSYCHIC SERVICES LTD"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:06:1f:ca:4d:5f:66:7d:cb:02:b9:e7:00:00:00:06:1f:ca"
      cert_thumbprint     = "B6ECF94395A0F8899B3EDC7875FFDCB3F24339B3"
      cert_valid_from     = "2025-12-31"
      cert_valid_to       = "2026-01-03"

      country             = "GB"
      state               = "Sheffield"
      locality            = "Sheffield"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:06:1f:ca:4d:5f:66:7d:cb:02:b9:e7:00:00:00:06:1f:ca"
      )
}
