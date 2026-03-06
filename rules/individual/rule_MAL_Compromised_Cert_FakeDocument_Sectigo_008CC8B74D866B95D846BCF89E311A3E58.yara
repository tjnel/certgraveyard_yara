import "pe"

rule MAL_Compromised_Cert_FakeDocument_Sectigo_008CC8B74D866B95D846BCF89E311A3E58 {
   meta:
      description         = "Detects FakeDocument with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-10"
      version             = "1.0"

      hash                = "ff8532b52c5d68cc45710dace36a2b9ac317159ba2cefd8e1c78269e1d13afab"
      malware             = "FakeDocument"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "MARSOY GRUP METAL HIRDAVAT INSAAT OTOMOTIV TIC LIMITED SIRKETI"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:8c:c8:b7:4d:86:6b:95:d8:46:bc:f8:9e:31:1a:3e:58"
      cert_thumbprint     = "0A4D93B2E39F6B19B8CDC025E8FE39910DFBAC66"
      cert_valid_from     = "2026-02-10"
      cert_valid_to       = "2027-02-10"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:8c:c8:b7:4d:86:6b:95:d8:46:bc:f8:9e:31:1a:3e:58"
      )
}
