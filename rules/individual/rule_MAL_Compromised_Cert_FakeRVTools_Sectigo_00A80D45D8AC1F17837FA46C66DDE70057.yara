import "pe"

rule MAL_Compromised_Cert_FakeRVTools_Sectigo_00A80D45D8AC1F17837FA46C66DDE70057 {
   meta:
      description         = "Detects FakeRVTools with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-06"
      version             = "1.0"

      hash                = "d0f5e98fb840fb5656d3f50613b6f1ec60e57392643159841bc1fa95396087a4"
      malware             = "FakeRVTools"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "Xiamen Lunwei Huage Network Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:a8:0d:45:d8:ac:1f:17:83:7f:a4:6c:66:dd:e7:00:57"
      cert_thumbprint     = "ACAD3EEB136194A8AAEB375A3BF0D1BF48E10577"
      cert_valid_from     = "2026-02-06"
      cert_valid_to       = "2027-02-06"

      country             = "CN"
      state               = "Fujian Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91350211MAE1BFAD45"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:a8:0d:45:d8:ac:1f:17:83:7f:a4:6c:66:dd:e7:00:57"
      )
}
