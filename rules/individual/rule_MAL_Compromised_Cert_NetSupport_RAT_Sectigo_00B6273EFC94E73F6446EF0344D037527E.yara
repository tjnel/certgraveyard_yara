import "pe"

rule MAL_Compromised_Cert_NetSupport_RAT_Sectigo_00B6273EFC94E73F6446EF0344D037527E {
   meta:
      description         = "Detects NetSupport RAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-12-26"
      version             = "1.0"

      hash                = "ccc3a92b91011399a12c48284aa8d3a1147e1972edaa8c57b4710c07c10cf221"
      malware             = "NetSupport RAT"
      malware_type        = "Remote access tool"
      malware_notes       = "The malware was disguised as a document provided as an application response, but installs NetSupport RAT"

      signer              = "Wuxi Aulan Metal Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:b6:27:3e:fc:94:e7:3f:64:46:ef:03:44:d0:37:52:7e"
      cert_thumbprint     = "CC6D0799149D3AA4709442248744A819956F2CE9"
      cert_valid_from     = "2025-12-26"
      cert_valid_to       = "2026-12-26"

      country             = "CN"
      state               = "Jiangsu Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91320214MA1XRMWC85"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:b6:27:3e:fc:94:e7:3f:64:46:ef:03:44:d0:37:52:7e"
      )
}
