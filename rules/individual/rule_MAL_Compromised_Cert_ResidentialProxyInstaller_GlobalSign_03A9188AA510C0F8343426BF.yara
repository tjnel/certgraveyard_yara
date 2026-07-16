import "pe"

rule MAL_Compromised_Cert_ResidentialProxyInstaller_GlobalSign_03A9188AA510C0F8343426BF {
   meta:
      description         = "Detects ResidentialProxyInstaller with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-04-26"
      version             = "1.0"

      hash                = "f5111a55125fcc4223805a676963852e9cf238287a51e4caad46791331127a24"
      malware             = "ResidentialProxyInstaller"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "WEILAI NETWORK TECHNOLOGY CO., LIMITED"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "03:a9:18:8a:a5:10:c0:f8:34:34:26:bf"
      cert_thumbprint     = "5CCC0717179EBC7C6165253405840FE33518E5D6"
      cert_valid_from     = "2023-04-26"
      cert_valid_to       = "2026-04-26"

      country             = "---"
      state               = "---"
      locality            = "---"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "03:a9:18:8a:a5:10:c0:f8:34:34:26:bf"
      )
}
