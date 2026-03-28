import "pe"

rule MAL_Compromised_Cert_FakePDF_NovaViewer_Sectigo_3CF1CF07647C6052688E66D3B2E179DF {
   meta:
      description         = "Detects FakePDF, NovaViewer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-04"
      version             = "1.0"

      hash                = "5fa5a32476d1e677e544e27d795a8c627b5ed9adf210d5c9b9626c1173115a62"
      malware             = "FakePDF, NovaViewer"
      malware_type        = "Unknown"
      malware_notes       = "The malware had behavior consistent with other fake PDF viewers such as GalacticPDF"

      signer              = "Xiamen Duohanbeiwei Network Co., Ltd"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "3c:f1:cf:07:64:7c:60:52:68:8e:66:d3:b2:e1:79:df"
      cert_thumbprint     = "8BB90CD512B2A0992771F65D41C37F0EBDD2801F"
      cert_valid_from     = "2026-02-04"
      cert_valid_to       = "2027-02-04"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350213MAE3YX8L38"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "3c:f1:cf:07:64:7c:60:52:68:8e:66:d3:b2:e1:79:df"
      )
}
