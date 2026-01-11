import "pe"

rule MAL_Compromised_Cert_RemoteManipulator_GlobalSign_6E4DA2A3CFA63A68B1259AD5 {
   meta:
      description         = "Detects RemoteManipulator with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-17"
      version             = "1.0"

      hash                = "43a8c1b43e946a20e1bfc549a38fd7a0b9f1efab2fe3e6a3c0b874584ddf0171"
      malware             = "RemoteManipulator"
      malware_type        = "Remote access tool"
      malware_notes       = "This is the second stage dropped by a fake crypto-wallet application: 03e91fbfc07c3dc4f50f550decf38e2816604d85f1f0deb136f922aa8fa55b2e"

      signer              = "JAGNANI CREATIONS PVT. LTD"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "6e:4d:a2:a3:cf:a6:3a:68:b1:25:9a:d5"
      cert_thumbprint     = "BF923693B067A3FED8F14AB34F7CF0FF9361D8DC"
      cert_valid_from     = "2025-07-17"
      cert_valid_to       = "2026-07-18"

      country             = "IN"
      state               = "Rajasthan"
      locality            = "Jaipur"
      email               = "jagnanicreation@gmail.com"
      rdn_serial_number   = "U24114RJ1992PTC006935"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "6e:4d:a2:a3:cf:a6:3a:68:b1:25:9a:d5"
      )
}
