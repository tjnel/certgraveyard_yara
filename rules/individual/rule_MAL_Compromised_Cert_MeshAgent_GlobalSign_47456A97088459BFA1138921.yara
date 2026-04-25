import "pe"

rule MAL_Compromised_Cert_MeshAgent_GlobalSign_47456A97088459BFA1138921 {
   meta:
      description         = "Detects MeshAgent with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-01-15"
      version             = "1.0"

      hash                = "d4f85f120a35332365566647b38b56090c6e89d52209fbf36f8aeeb1a05b9b77"
      malware             = "MeshAgent"
      malware_type        = "Remote access tool"
      malware_notes       = "This signer appears to be used with multiple remote access tools. Reported here on Twitter: https://x.com/johnk3r/status/2047121689364853181?s=20 . Appears to be sent via phishing."

      signer              = "PACN TECNOLOGIA E SOFTWARE LTDA"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "47:45:6a:97:08:84:59:bf:a1:13:89:21"
      cert_thumbprint     = "7041E43D4F92AB49683E8EBE167E077753F1D3E5"
      cert_valid_from     = "2024-01-15"
      cert_valid_to       = "2027-01-15"

      country             = "BR"
      state               = "SAO PAULO"
      locality            = "SAO PAULO"
      email               = "contato@pacnsoftware.org"
      rdn_serial_number   = "52.886.760/0001-41"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "47:45:6a:97:08:84:59:bf:a1:13:89:21"
      )
}
