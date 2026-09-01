import "pe"

rule MAL_Compromised_Cert_FakeSoftware_Sectigo_A571641AA9CF5DED05D1E4AD27DB6F0 {
   meta:
      description         = "Detects FakeSoftware with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-19"
      version             = "1.0"

      hash                = "ab14e1cd7f89587dafffb74fdb5005a89a7d02c52905aa4c110b2190d35bb3ce"
      malware             = "FakeSoftware"
      malware_type        = "Unknown"
      malware_notes       = "Fake Rust RMM, C2 stored in blockchain, executes JS received remotely"

      signer              = "Lway Firmware"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "a5:71:64:1a:a9:cf:5d:ed:05:d1:e4:ad:27:db:6f:0"
      cert_thumbprint     = "94534dfa980037b87d48fea0a41bd38133693fcc"
      cert_valid_from     = "2026-03-19"
      cert_valid_to       = "2027-06-17"

      country             = "FI"
      state               = "Uusimaa"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "a5:71:64:1a:a9:cf:5d:ed:05:d1:e4:ad:27:db:6f:0"
      )
}
