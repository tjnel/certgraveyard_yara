import "pe"

rule MAL_Compromised_Cert_Unknown_Sectigo_B683AFC8350CA6388FFB39194E094B09 {
   meta:
      description         = "Detects Unknown with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-10-17"
      version             = "1.0"

      hash                = "698ba27e47db93bf9d0624e42b64037dd0b9e29d5a01e502d6a93dee3f96cb5d"
      malware             = "Unknown"
      malware_type        = "Backdoor"
      malware_notes       = "https://rogueauthority.org/signed-putty-installer-nodejs-loader"

      signer              = "Lille Lykke Gave og Interiør ANS"
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "b6:83:af:c8:35:0c:a6:38:8f:fb:39:19:4e:09:4b:09"
      cert_thumbprint     = "e704929aa80a5eaeed9f88a9b01914735b897533"
      cert_valid_from     = "2026-10-17"
      cert_valid_to       = "2027-10-17"

      country             = "NO"
      state               = "Østfold"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "b6:83:af:c8:35:0c:a6:38:8f:fb:39:19:4e:09:4b:09"
      )
}
