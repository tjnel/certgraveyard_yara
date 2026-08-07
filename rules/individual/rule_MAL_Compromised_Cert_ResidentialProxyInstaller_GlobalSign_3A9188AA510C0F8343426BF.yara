import "pe"

rule MAL_Compromised_Cert_ResidentialProxyInstaller_GlobalSign_3A9188AA510C0F8343426BF {
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
      cert_serial         = "3a:91:88:aa:51:0c:0f:83:43:42:6b:f"
      cert_thumbprint     = "5ccc0717179ebc7c6165253405840fe33518e5d6"
      cert_valid_from     = "2023-04-26"
      cert_valid_to       = "2026-04-26"

      country             = "GB"
      state               = "London"
      locality            = "London"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "3a:91:88:aa:51:0c:0f:83:43:42:6b:f"
      )
}
