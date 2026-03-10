import "pe"

rule MAL_Compromised_Cert_MeshAgent_GlobalSign_2B2E6AABDD8EF6346604ABBF {
   meta:
      description         = "Detects MeshAgent with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-11-10"
      version             = "1.0"

      hash                = "dbfe1f915f40122a336cd5d0de802a6f3ec0204ab75321934a06dafbc1964446"
      malware             = "MeshAgent"
      malware_type        = "Unknown"
      malware_notes       = "Fake VMWare installer leading to MeshCentral RMM - C2: 103.65.230.86"

      signer              = "Pacex Learning Private Limited"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "2b:2e:6a:ab:dd:8e:f6:34:66:04:ab:bf"
      cert_thumbprint     = "39CABAB57736654FC72EA10D626641ED52299356"
      cert_valid_from     = "2025-11-10"
      cert_valid_to       = "2026-11-11"

      country             = "???"
      state               = "???"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "2b:2e:6a:ab:dd:8e:f6:34:66:04:ab:bf"
      )
}
