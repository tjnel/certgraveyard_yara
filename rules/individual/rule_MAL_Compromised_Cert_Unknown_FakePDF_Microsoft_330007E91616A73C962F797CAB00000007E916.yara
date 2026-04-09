import "pe"

rule MAL_Compromised_Cert_Unknown_FakePDF_Microsoft_330007E91616A73C962F797CAB00000007E916 {
   meta:
      description         = "Detects Unknown,FakePDF with compromised cert (Microsoft)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-07"
      version             = "1.0"

      hash                = "5ef56887934c2d8bd200e0068ab2d3674335001dc527698b38deaac973191c5f"
      malware             = "Unknown,FakePDF"
      malware_type        = "Unknown"
      malware_notes       = "PDFGear"

      signer              = "Miguel GUTIERREZLUPERCIO"
      cert_issuer_short   = "Microsoft"
      cert_issuer         = "Microsoft ID Verified CS EOC CA 02"
      cert_serial         = "33:00:07:e9:16:16:a7:3c:96:2f:79:7c:ab:00:00:00:07:e9:16"
      cert_thumbprint     = "6DD1383565C90B6596BA30E893EA403BF80A82CB"
      cert_valid_from     = "2026-04-07"
      cert_valid_to       = "2026-04-10"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Microsoft ID Verified CS EOC CA 02" and
         sig.serial == "33:00:07:e9:16:16:a7:3c:96:2f:79:7c:ab:00:00:00:07:e9:16"
      )
}
