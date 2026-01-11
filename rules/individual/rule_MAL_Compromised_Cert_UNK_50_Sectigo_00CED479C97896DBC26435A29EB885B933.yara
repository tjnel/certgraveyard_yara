import "pe"

rule MAL_Compromised_Cert_UNK_50_Sectigo_00CED479C97896DBC26435A29EB885B933 {
   meta:
      description         = "Detects UNK-50 with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-13"
      version             = "1.0"

      hash                = "e2398c154858077cdc6f5ba5c031a7af3380fb47d493076098d5bf11655d4f78"
      malware             = "UNK-50"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "FAV MAKINA OTOM. DANIS. ITHALAT IHR. SAN. VE TIC. LTD. STI."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:ce:d4:79:c9:78:96:db:c2:64:35:a2:9e:b8:85:b9:33"
      cert_thumbprint     = "8FCB2FE970729C95EE0A74A3A59C95F818721E35"
      cert_valid_from     = "2025-11-13"
      cert_valid_to       = "2026-11-13"

      country             = "TR"
      state               = "Bursa"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "127520"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:ce:d4:79:c9:78:96:db:c2:64:35:a2:9e:b8:85:b9:33"
      )
}
