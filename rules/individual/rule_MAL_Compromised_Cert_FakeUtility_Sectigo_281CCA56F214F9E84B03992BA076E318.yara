import "pe"

rule MAL_Compromised_Cert_FakeUtility_Sectigo_281CCA56F214F9E84B03992BA076E318 {
   meta:
      description         = "Detects FakeUtility with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-04-17"
      version             = "1.0"

      hash                = "2c253d8131cf8a948115884467aeeba28f43a85a289b730b5e490fb59ad4c921"
      malware             = "FakeUtility"
      malware_type        = "Unknown"
      malware_notes       = "Shared as bundle file on malicious \"PC Cleaner\" and \"Screenshot Tool\" msix installers. Connects to https://api1.storeappsupdatesapi.xyz/ping waiting for updates on infected machines"

      signer              = "OC Agro ApS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "28:1c:ca:56:f2:14:f9:e8:4b:03:99:2b:a0:76:e3:18"
      cert_thumbprint     = "D54C2FD588EE88CC00025850DC1FE412572042E1"
      cert_valid_from     = "2026-04-17"
      cert_valid_to       = "2027-04-17"

      country             = "DK"
      state               = "Midtjylland"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "36932813"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "28:1c:ca:56:f2:14:f9:e8:4b:03:99:2b:a0:76:e3:18"
      )
}
