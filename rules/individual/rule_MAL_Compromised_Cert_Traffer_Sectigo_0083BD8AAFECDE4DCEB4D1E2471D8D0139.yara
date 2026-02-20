import "pe"

rule MAL_Compromised_Cert_Traffer_Sectigo_0083BD8AAFECDE4DCEB4D1E2471D8D0139 {
   meta:
      description         = "Detects Traffer with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-01-19"
      version             = "1.0"

      hash                = "5661526b77a414058208171fbd529197d78f54e682cb054b74dda0842416ff2f"
      malware             = "Traffer"
      malware_type        = "Unknown"
      malware_notes       = "Fake meeting software targeting cryptocurrencies users worldwide"

      signer              = "Linyi Rongyun Network Information Service Co., Ltd."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "00:83:bd:8a:af:ec:de:4d:ce:b4:d1:e2:47:1d:8d:01:39"
      cert_thumbprint     = "58EA3E0A8D5AC02838006267BA1C63BB3C2E7285"
      cert_valid_from     = "2026-01-19"
      cert_valid_to       = "2027-01-19"

      country             = "CN"
      state               = "Shandong Sheng"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "91371311312720445T"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "00:83:bd:8a:af:ec:de:4d:ce:b4:d1:e2:47:1d:8d:01:39"
      )
}
