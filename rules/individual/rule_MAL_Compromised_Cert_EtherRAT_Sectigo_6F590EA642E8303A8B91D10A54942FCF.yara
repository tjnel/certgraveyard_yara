import "pe"

rule MAL_Compromised_Cert_EtherRAT_Sectigo_6F590EA642E8303A8B91D10A54942FCF {
   meta:
      description         = "Detects EtherRAT with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-22"
      version             = "1.0"

      hash                = "1b61b95a61996b44322e9841af2fa2b63fcdd18a569f16fa8acd30eb8d8ac854"
      malware             = "EtherRAT"
      malware_type        = "Remote access tool"
      malware_notes       = ""

      signer              = "KARA-TASH I KO, OSOO"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "6f:59:0e:a6:42:e8:30:3a:8b:91:d1:0a:54:94:2f:cf"
      cert_thumbprint     = "15b8e84eb703b5ccd385762c58707a1664a099e5"
      cert_valid_from     = "2026-04-22"
      cert_valid_to       = "2027-04-22"

      country             = "KG"
      state               = "Osh"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "6f:59:0e:a6:42:e8:30:3a:8b:91:d1:0a:54:94:2f:cf"
      )
}
