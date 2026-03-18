import "pe"

rule MAL_Compromised_Cert_Fake_F5Updater_SSL_com_4FF0CAF9735335B3C10FABF148214582 {
   meta:
      description         = "Detects Fake-F5Updater with compromised cert (SSL.com)"
      author              = "TNEL (https://github.com/tjnel/certgraveyard_yara)"
      reference           = "https://certgraveyard.org"
      date                = "2023-12-06"
      version             = "1.0"

      hash                = "fe07dca68f288a4f6d7cbd34d79bb70bc309635876298d4fde33c25277e30bd2"
      malware             = "Fake-F5Updater"
      malware_type        = "Initial access tool"
      malware_notes       = "Initial lure is a tool to update an F5 Client, check's users IP and connects to Telegram."

      signer              = "Skytec Global Ltd"
      cert_issuer_short   = "SSL.com"
      cert_issuer         = "SSL.com Code Signing Intermediate CA RSA R1"
      cert_serial         = "4f:f0:ca:f9:73:53:35:b3:c1:0f:ab:f1:48:21:45:82"
      cert_thumbprint     = "2C4D35D1166A96D14088645FA3807E40A02B64BD"
      cert_valid_from     = "2023-12-06"
      cert_valid_to       = "2024-12-05"

      country             = "GB"
      state               = "???"
      locality            = "Billingham"
      email               = "???"
      rdn_serial_number   = "Not Specified"

   condition:
      uint16(0) == 0x5a4d and
      for any sig in pe.signatures : (
         sig.issuer contains "SSL.com Code Signing Intermediate CA RSA R1" and
         sig.serial == "4f:f0:ca:f9:73:53:35:b3:c1:0f:ab:f1:48:21:45:82"
      )
}
