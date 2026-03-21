import "pe"

rule MAL_Compromised_Cert_FakePDF_NovaViewer_Sectigo_67BEA002D62E1831CC2612ADB8E1B2CE {
   meta:
      description         = "Detects FakePDF, NovaViewer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-23"
      version             = "1.0"

      hash                = "a63cb8de82ca6f2739e46a73c59d607dcf34e683c396aa0e4a4ce96d3666bfcf"
      malware             = "FakePDF, NovaViewer"
      malware_type        = "Unknown"
      malware_notes       = "The malware had behavior consistent with other fake PDF viewers such as GalacticPDF. This cert was then also used by a Russian cybercrime actor."

      signer              = "Xiamen Xisu Technology Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "67:be:a0:02:d6:2e:18:31:cc:26:12:ad:b8:e1:b2:ce"
      cert_thumbprint     = "BAF6F7831218C352B4CB784EB54A6E86319138AC"
      cert_valid_from     = "2026-01-23"
      cert_valid_to       = "2027-01-23"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350200MA35CYLRX4"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "67:be:a0:02:d6:2e:18:31:cc:26:12:ad:b8:e1:b2:ce"
      )
}
