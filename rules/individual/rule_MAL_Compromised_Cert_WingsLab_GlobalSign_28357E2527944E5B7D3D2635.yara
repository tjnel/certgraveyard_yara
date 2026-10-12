import "pe"

rule MAL_Compromised_Cert_WingsLab_GlobalSign_28357E2527944E5B7D3D2635 {
   meta:
      description         = "Detects WingsLab with compromised cert (GlobalSign)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-09-16"
      version             = "1.0"

      hash                = "560f576d60dfb1e61eed758e06910b32a42145ecb8271f97fdc76789f6a27659"
      malware             = "WingsLab"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "HOLLIDAY DIGITAL LLC"
      cert_issuer_short   = "GlobalSign"
      cert_issuer         = "GlobalSign GCC R45 EV CodeSigning CA 2020"
      cert_serial         = "28:35:7e:25:27:94:4e:5b:7d:3d:26:35"
      cert_thumbprint     = "072dbe614ec99a002f49a4de6b95b57271d18ac7"
      cert_valid_from     = "2026-09-16"
      cert_valid_to       = "2027-09-17"

      country             = "US"
      state               = "New York"
      locality            = "Albany"
      email               = "alexis@hollidaydigital.com"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "GlobalSign GCC R45 EV CodeSigning CA 2020" and
         sig.serial == "28:35:7e:25:27:94:4e:5b:7d:3d:26:35"
      )
}
