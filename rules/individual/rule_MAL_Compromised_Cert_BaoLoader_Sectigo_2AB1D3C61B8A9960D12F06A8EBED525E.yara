import "pe"

rule MAL_Compromised_Cert_BaoLoader_Sectigo_2AB1D3C61B8A9960D12F06A8EBED525E {
   meta:
      description         = "Detects BaoLoader with compromised cert (Sectigo)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2024-06-20"
      version             = "1.0"

      hash                = "e06c05b3e19e78108a4f4174219862c4680dd1ee4b5dbef18b9295fc846eda98"
      malware             = "BaoLoader"
      malware_type        = "Trojan"
      malware_notes       = ""

      signer              = "ECLIPSE MEDIA INC."
      cert_issuer_short   = "Sectigo"
      cert_issuer         = "Sectigo Public Code Signing CA EV R36"
      cert_serial         = "2a:b1:d3:c6:1b:8a:99:60:d1:2f:06:a8:eb:ed:52:5e"
      cert_thumbprint     = "2983A181ADC283981EAAD2AC989034031959526D"
      cert_valid_from     = "2024-06-20"
      cert_valid_to       = "2027-06-21"

      country             = "PA"
      state               = "Panamá"
      locality            = "???"
      email               = "???"
      rdn_serial_number   = "155704432"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "Sectigo Public Code Signing CA EV R36" and
         sig.serial == "2a:b1:d3:c6:1b:8a:99:60:d1:2f:06:a8:eb:ed:52:5e"
      )
}
