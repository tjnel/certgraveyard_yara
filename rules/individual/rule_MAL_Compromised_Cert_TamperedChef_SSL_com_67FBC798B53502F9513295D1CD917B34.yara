import "pe"

rule MAL_Compromised_Cert_TamperedChef_SSL_com_67FBC798B53502F9513295D1CD917B34 {
   meta:
      description         = "Detects TamperedChef with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2026-03-18"
      version             = "1.0"

      hash                = "40798b13e16d6a83cf5b828d7eca110b433eaabf8ca5c83511425eb24bbaee4f"
      malware             = "TamperedChef"
      malware_type        = "Unknown"
      malware_notes       = ""

      signer              = "ROAD MEDIA PASS LIMITED"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA ECC R2"
      cert_serial         = "67:fb:c7:98:b5:35:02:f9:51:32:95:d1:cd:91:7b:34"
      cert_thumbprint     = "4b94ac493d0cdf36018f79b16f223bda014e6276"
      cert_valid_from     = "2026-03-18"
      cert_valid_to       = "2027-03-18"

      country             = "GB"
      state               = "---"
      locality            = "Watford"
      email               = "---"
      rdn_serial_number   = ""

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA ECC R2" and
         sig.serial == "67:fb:c7:98:b5:35:02:f9:51:32:95:d1:cd:91:7b:34"
      )
}
