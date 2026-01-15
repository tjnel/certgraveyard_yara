import "pe"

rule MAL_Compromised_Cert_ZhongStealer_SSL_com_7D0FA22D5E5F69EA34350A46FE01289F {
   meta:
      description         = "Detects ZhongStealer with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2025-07-25"
      version             = "1.0"

      hash                = "f7d133a1fe5febb0e3fafaade59310a20f60e38f17331f1043956e8e3a3ca770"
      malware             = "ZhongStealer"
      malware_type        = "Unknown"
      malware_notes       = "An infostealer used by a Chinese cybercrime group tracked as Golden eye dog. Pulls second stage from legitimate CDN."

      signer              = "Fuet Corp."
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com EV Code Signing Intermediate CA RSA R3"
      cert_serial         = "7d:0f:a2:2d:5e:5f:69:ea:34:35:0a:46:fe:01:28:9f"
      cert_thumbprint     = "1D72DDC626E38C73D88D8843F7B4DE28623B729D"
      cert_valid_from     = "2025-07-25"
      cert_valid_to       = "2026-07-25"

      country             = "US"
      state               = "New York"
      locality            = "New York City"
      email               = "???"
      rdn_serial_number   = "10255002"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com EV Code Signing Intermediate CA RSA R3" and
         sig.serial == "7d:0f:a2:2d:5e:5f:69:ea:34:35:0a:46:fe:01:28:9f"
      )
}
