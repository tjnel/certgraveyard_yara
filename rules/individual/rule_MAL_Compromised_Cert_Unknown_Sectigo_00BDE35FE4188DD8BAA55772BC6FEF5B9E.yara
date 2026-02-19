import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_00BDE35FE4188DD8BAA55772BC6FEF5B9E {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-02-03"
      version             = "1.0"

      hash                = "e06dbe87f6cdcfc942f274c4d7883a5ebadf48b7d5eab2a9ef0e900783a8e915"
      malware             = "Unknown"
      malware_type        = "Unknown"
      malware_notes       = "Putty build delivered from the malicious InstallsLab PPI network"

      signer              = "Cage And Stone Fabrication LLC"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV E36"
      cert_serial         = "00:bd:e3:5f:e4:18:8d:d8:ba:a5:57:72:bc:6f:ef:5b:9e"
      cert_thumbprint     = "DB97EB5BB01780752703DF68B7EA95F5131F46D3"
      cert_valid_from     = "2026-02-03"
      cert_valid_to       = "2027-02-03"

      country             = "US"
      state               = "Arizona"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "23392421"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV E36" and
         sig.serial == "00:bd:e3:5f:e4:18:8d:d8:ba:a5:57:72:bc:6f:ef:5b:9e"
      )
}
